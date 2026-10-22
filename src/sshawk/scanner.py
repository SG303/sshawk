"""Parallel scanning of many targets, with optional CDP/LLDP crawling."""

from __future__ import annotations

import ipaddress
import logging
import re
import threading
import time
from collections.abc import Callable, Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path

from sshawk.credentials import Credential
from sshawk.models import DeviceInfo, Status
from sshawk.session import SessionError, open_session
from sshawk.targets import Target, parse_targets

log = logging.getLogger(__name__)

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass
class ScanOptions:
    workers: int = 20
    timeout: float = 10
    device_type: str | None = None  # skip detection and use this driver for every target
    neighbors: bool = False  # collect CDP/LLDP neighbors
    crawl: bool = False  # follow neighbors' management addresses (implies neighbors)
    crawl_depth: int = 3  # hops away from the given targets
    scope: list[Network] = field(default_factory=list)  # crawl only into these networks
    exclude: list[Network] = field(default_factory=list)  # never connect to these
    save_raw: Path | None = None  # write raw command outputs per device here
    port_check: bool = True
    port: int = 22  # SSH port for targets without an explicit one, and for crawled neighbors


class _CredentialOrder:
    """Tries the most recently successful credential first, to avoid needless failed logins."""

    def __init__(self, credentials: Sequence[Credential]):
        self._order = list(credentials)
        self._lock = threading.Lock()

    def current(self) -> list[Credential]:
        with self._lock:
            return list(self._order)

    def succeeded(self, label: str) -> None:
        with self._lock:
            for index, cred in enumerate(self._order):
                if cred.label == label and index:
                    self._order.insert(0, self._order.pop(index))
                    break


def scan(
    targets: Iterable[str | Target],
    credentials: Sequence[Credential],
    options: ScanOptions | None = None,
    progress: Callable[[DeviceInfo], None] | None = None,
    **kwargs: object,
) -> list[DeviceInfo]:
    """Scan targets in parallel and return one DeviceInfo per target (failures included).

    ``targets`` accepts the same specs as the CLI (hosts, CIDRs, ranges). Options can be
    passed as a ScanOptions or as keyword arguments, e.g. ``scan(["10.0.0.0/24"], creds,
    workers=50, neighbors=True)``. ``progress`` is called with each finished DeviceInfo.
    """
    options = options or ScanOptions()
    for key, value in kwargs.items():
        if not hasattr(options, key):
            raise TypeError(f"unknown scan option {key!r}")
        setattr(options, key, value)
    if options.crawl:
        options.neighbors = True

    targets = list(targets)
    initial = [t for t in targets if isinstance(t, Target)]
    initial += parse_targets([t for t in targets if not isinstance(t, Target)], options.port)
    initial = [t for t in initial if not _excluded(t.host, options.exclude)]

    order = _CredentialOrder(credentials)
    results: list[DeviceInfo] = []
    seen_targets: set[str] = {t.host for t in initial}
    seen_names: set[str] = set()
    level: list[tuple[Target, str]] = [(t, "") for t in initial]
    depth = 0

    with ThreadPoolExecutor(max_workers=max(1, options.workers)) as pool:
        while level:
            futures = {
                pool.submit(scan_one, target, order, options, via): target for target, via in level
            }
            finished = []
            for future in as_completed(futures):
                info = future.result()
                finished.append(info)
                if progress:
                    progress(info)
            results.extend(finished)

            if not options.crawl or depth >= options.crawl_depth:
                break
            depth += 1
            level = []
            for info in finished:
                if info.hostname:
                    seen_names.add(_short_name(info.hostname))
            for info in finished:
                for neighbor in info.neighbors:
                    candidate = _crawl_candidate(neighbor.remote_ip, options)
                    if not candidate or candidate in seen_targets:
                        continue
                    if (
                        neighbor.remote_hostname
                        and _short_name(neighbor.remote_hostname) in seen_names
                    ):
                        continue
                    seen_targets.add(candidate)
                    via = f"{info.hostname or info.host} ({neighbor.protocol})"
                    level.append((Target(candidate, options.port), via))

    return results


def scan_one(
    target: Target | str,
    credentials: Sequence[Credential] | _CredentialOrder,
    options: ScanOptions | None = None,
    discovered_via: str = "",
) -> DeviceInfo:
    """Collect one target. Never raises; failures are reported in DeviceInfo.status/error."""
    options = options or ScanOptions()
    if isinstance(target, str):
        target = parse_targets([target], options.port)[0]
    order = (
        credentials if isinstance(credentials, _CredentialOrder) else _CredentialOrder(credentials)
    )
    started = time.monotonic()
    info = DeviceInfo(host=target.host, port=target.port, discovered_via=discovered_via)
    raw: dict[str, str] = {}

    try:
        session = open_session(
            target,
            order.current(),
            device_type=options.device_type,
            timeout=options.timeout,
            port_check=options.port_check,
        )
    except SessionError as exc:
        info.status, info.error = exc.status, str(exc)
    except Exception as exc:  # noqa: BLE001 - one bad device must not stop the scan
        log.exception("%s: unexpected error", target)
        info.status, info.error = Status.ERROR, f"{type(exc).__name__}: {exc}"
    else:
        with session:
            order.succeeded(session.credential.label)
            info = session.new_info()
            info.discovered_via = discovered_via
            raw = session.raw
            try:
                session.collect(neighbors=options.neighbors, info=info)
            except Exception as exc:  # noqa: BLE001
                log.debug("%s: collection failed", target, exc_info=True)
                info.error = f"{type(exc).__name__}: {exc}"
                info.status = Status.PARTIAL if (info.version or info.model) else Status.ERROR
            else:
                if info.warnings and not (info.version and info.model):
                    info.status = Status.PARTIAL

    info.extra["duration_s"] = round(time.monotonic() - started, 1)
    if options.save_raw and raw:
        _save_raw(options.save_raw, info, raw)
    log.info("%s: %s %s", target, info.status, info.error)
    return info


def parse_networks(specs: Iterable[str]) -> list[Network]:
    return [ipaddress.ip_network(s.strip(), strict=False) for s in specs if s.strip()]


def _crawl_candidate(address: str, options: ScanOptions) -> str | None:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return None
    if options.scope:
        # An explicit scope wins, even for unusual ranges (lab setups on loopback).
        if not any(ip in net for net in options.scope):
            return None
    elif ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        return None
    if _excluded(str(ip), options.exclude):
        return None
    return str(ip)


def _excluded(host: str, exclude: list[Network]) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(ip in net for net in exclude)


def _short_name(hostname: str) -> str:
    return hostname.split(".", 1)[0].lower()


def _save_raw(directory: Path, info: DeviceInfo, raw: dict[str, str]) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    name = re.sub(r"[^\w.-]+", "_", f"{info.host}_{info.hostname}".strip("_"))
    lines = [f"# host: {info.host}  device_type: {info.device_type}  status: {info.status}"]
    for command, output in raw.items():
        lines += ["", f"### {command}", output.rstrip()]
    (directory / f"{name}.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
