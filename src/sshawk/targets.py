"""Parse target specifications into individual hosts.

Accepted forms (mixable, also one per line in a targets file; ``#`` starts a comment):

* ``10.0.0.1``                  single host
* ``10.0.0.0/24``               network (network/broadcast addresses skipped)
* ``10.0.0.10-10.0.0.50``       inclusive range
* ``10.0.0.10-50``              short range, last octet only
* ``switch01.example.com``      hostname
* any of the above with ``:port`` for a non-standard SSH port (IPv4/hostnames only)
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

MAX_TARGETS = 65536

_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?"
_HOSTNAME = re.compile(rf"^(?=.{{1,253}}$){_LABEL}(?:\.{_LABEL})*$")


class TargetError(ValueError):
    pass


@dataclass(frozen=True, order=True)
class Target:
    host: str
    port: int = 22

    def __str__(self) -> str:
        return self.host if self.port == 22 else f"{self.host}:{self.port}"


def parse_targets(specs: Iterable[str], default_port: int = 22) -> list[Target]:
    """Expand target specs into a de-duplicated list, preserving first-seen order."""
    seen: dict[Target, None] = {}
    for spec in specs:
        for target in _expand(spec.strip(), default_port):
            seen.setdefault(target)
            if len(seen) > MAX_TARGETS:
                raise TargetError(f"more than {MAX_TARGETS} targets; split the scan")
    return list(seen)


def read_targets_file(path: str | Path) -> list[str]:
    lines = []
    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            lines.extend(line.replace(",", " ").split())
    return lines


def _split_port(spec: str, default_port: int) -> tuple[str, int]:
    if spec.count(":") == 1:
        host, port = spec.rsplit(":", 1)
        if not port.isdigit() or not 0 < int(port) < 65536:
            raise TargetError(f"invalid port in {spec!r}")
        return host, int(port)
    return spec, default_port


def _expand(spec: str, default_port: int) -> Iterator[Target]:
    if not spec:
        return
    spec, port = _split_port(spec, default_port)

    if "/" in spec:
        try:
            network = ipaddress.ip_network(spec, strict=False)
        except ValueError as exc:
            raise TargetError(f"invalid network {spec!r}: {exc}") from exc
        if network.num_addresses > MAX_TARGETS:
            raise TargetError(f"network {spec} is too large (max {MAX_TARGETS} addresses)")
        hosts = list(network.hosts()) or [network.network_address]
        for address in hosts:
            yield Target(str(address), port)
        return

    if "-" in spec and _looks_like_ip_range(spec):
        start_text, end_text = spec.split("-", 1)
        start = _ip(start_text)
        if end_text.isdigit():
            prefix = start_text.rsplit(".", 1)[0]
            end = _ip(f"{prefix}.{end_text}")
        else:
            end = _ip(end_text)
        if start.version != end.version or int(end) < int(start):
            raise TargetError(f"invalid range {spec!r}")
        if int(end) - int(start) >= MAX_TARGETS:
            raise TargetError(f"range {spec} is too large (max {MAX_TARGETS} addresses)")
        for value in range(int(start), int(end) + 1):
            yield Target(str(ipaddress.ip_address(value)), port)
        return

    try:
        yield Target(str(ipaddress.ip_address(spec)), port)
        return
    except ValueError:
        pass
    if re.fullmatch(r"[\d.]+", spec):
        raise TargetError(f"invalid IP address {spec!r}")
    if _HOSTNAME.match(spec):
        yield Target(spec, port)
        return
    raise TargetError(f"cannot parse target {spec!r}")


def _looks_like_ip_range(spec: str) -> bool:
    start = spec.split("-", 1)[0]
    try:
        ipaddress.ip_address(start)
    except ValueError:
        return False
    return True


def _ip(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        return ipaddress.ip_address(text)
    except ValueError as exc:
        raise TargetError(f"invalid IP address {text!r}") from exc
