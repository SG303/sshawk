"""SSH sessions: login with credential fallback, platform detection, data collection."""

from __future__ import annotations

import contextlib
import logging
import re
import socket
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import paramiko
from netmiko import (
    BaseConnection,
    ConnectHandler,
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
    redispatch,
)

from sshawk.credentials import Credential
from sshawk.drivers import DRIVERS, Driver, driver_for
from sshawk.drivers.base import parse_textfsm
from sshawk.models import DeviceInfo, Status
from sshawk.targets import Target

log = logging.getLogger(__name__)

_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b[()][A-Z0-9]|\x1b[=>EM78]")
_PAGER = re.compile(
    r"--\s*more\s*--|---- more ----|press <?space>? to continue|next page:|\(q = quit\)",
    re.IGNORECASE,
)
_ANY_KEY = re.compile(r"press any key to continue", re.IGNORECASE)
# A CLI prompt: Cisco "sw1#", Huawei "<sw1>", EXOS "* sw1.3 #", VOSS "sw1:1>", Aruba "sw1#".
_PROMPT = re.compile(r"^(?:\* )?(?=[^\n]*\w)[\w.\-:()/@<\[\] ]{1,80}[>#\]]\s?$")


class SessionError(Exception):
    def __init__(self, status: Status, message: str):
        super().__init__(message)
        self.status = status


def clean(text: str) -> str:
    text = _ANSI.sub("", text).replace("\r\n", "\n").replace("\r", "\n")
    return text.replace("\x08", "")


def check_port(host: str, port: int, timeout: float) -> None:
    """Fail fast with UNREACHABLE if nothing listens on the SSH port."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
    except TimeoutError as exc:
        raise SessionError(Status.UNREACHABLE, f"tcp/{port} timed out") from exc
    except OSError as exc:
        raise SessionError(Status.UNREACHABLE, f"tcp/{port}: {exc.strerror or exc}") from exc


class Session:
    """A logged-in, platform-aware SSH session to one device.

    Usually created with :func:`sshawk.connect`::

        with sshawk.connect("10.0.0.1", credentials) as session:
            print(session.device_type)
            print(session.send("show clock"))
            info = session.collect()
    """

    def __init__(
        self,
        target: Target,
        conn: BaseConnection,
        driver: type[Driver],
        credential: Credential,
        ssh_banner: str = "",
    ):
        self.target = target
        self.conn = conn
        self.driver_class = driver
        self.credential = credential
        self.ssh_banner = ssh_banner
        self.raw: dict[str, str] = {}

    @property
    def device_type(self) -> str:
        return self.driver_class.device_type

    def new_info(self) -> DeviceInfo:
        info = DeviceInfo(host=self.target.host, port=self.target.port, status=Status.OK)
        info.credential = self.credential.label
        info.device_type = self.device_type
        if self.ssh_banner:
            info.extra["ssh_banner"] = self.ssh_banner
        return info

    def collect(self, neighbors: bool = False, info: DeviceInfo | None = None) -> DeviceInfo:
        """Collect inventory (and optionally CDP/LLDP neighbors) into a DeviceInfo."""
        info = info or self.new_info()
        driver = self.driver_class(self.conn, info, self.raw)
        driver.collect(neighbors=neighbors)
        return info

    def send(self, command: str, parse: bool | str = False, read_timeout: float = 60) -> Any:
        """Run any command. With ``parse=True`` the output is parsed with the matching
        TextFSM template (``<device_type>_<command>``); pass a template name to choose one.
        """
        output = self.conn.send_command(command, read_timeout=read_timeout)
        self.raw[command] = output
        if not parse:
            return output
        template = parse if isinstance(parse, str) else _template_name(self.device_type, command)
        return parse_textfsm(template, output)

    def close(self) -> None:
        try:
            self.conn.disconnect()
        except Exception:  # noqa: BLE001 - best effort on teardown
            log.debug("%s: error while disconnecting", self.target, exc_info=True)

    def __enter__(self) -> Session:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def __repr__(self) -> str:
        return f"<Session {self.target} {self.device_type} as {self.credential.label}>"


def _template_name(device_type: str, command: str) -> str:
    platform = {"cisco_ios": "cisco_ios", "huawei": "huawei_vrp"}.get(device_type, device_type)
    return f"{platform}_{command.strip().replace(' ', '_')}"


def open_session(
    target: Target | str,
    credentials: Sequence[Credential],
    device_type: str | None = None,
    timeout: float = 10,
    port_check: bool = True,
    session_log: str | Path | None = None,
    **netmiko_kwargs: Any,
) -> Session:
    """Log in with the first working credential and return a platform-aware Session.

    Raises SessionError with a Status describing why the device could not be used.
    """
    if isinstance(target, str):
        from sshawk.targets import parse_targets

        target = parse_targets([target])[0]
    if not credentials:
        raise SessionError(Status.ERROR, "no credentials given")
    driver = driver_for(device_type) if device_type and device_type != "autodetect" else None

    if port_check:
        check_port(target.host, target.port, timeout=min(timeout, 5))

    conn, credential = _login(target, credentials, driver, timeout, session_log, netmiko_kwargs)
    try:
        banner = _remote_version(conn)
        if driver is None:
            driver = detect(conn, target)
            log.info("%s: detected %s", target, driver.device_type)
            redispatch(conn, driver.device_type)
        if credential.secret and driver.device_type == "cisco_ios" and not conn.check_enable_mode():
            try:
                conn.enable()
            except (ValueError, NetmikoAuthenticationException) as exc:
                log.warning("%s: enable failed: %s", target, exc)
        return Session(target, conn, driver, credential, banner)
    except SessionError:
        _safe_disconnect(conn)
        raise
    except Exception as exc:
        _safe_disconnect(conn)
        raise SessionError(Status.ERROR, f"session setup failed: {exc}") from exc


def _login(
    target: Target,
    credentials: Sequence[Credential],
    driver: type[Driver] | None,
    timeout: float,
    session_log: str | Path | None,
    extra: dict[str, Any],
) -> tuple[BaseConnection, Credential]:
    failures = []
    for credential in credentials:
        params: dict[str, Any] = {
            "device_type": driver.device_type if driver else "terminal_server",
            "host": target.host,
            "port": target.port,
            "username": credential.username,
            "password": credential.password,
            "secret": credential.secret,
            "conn_timeout": timeout,
            "auth_timeout": timeout + 5,
            "banner_timeout": timeout + 5,
            "timeout": max(timeout, 30),
            "allow_agent": False,
            "use_keys": False,
        }
        if session_log:
            params["session_log"] = str(session_log)
        params.update(extra)
        try:
            return ConnectHandler(**params), credential
        except NetmikoAuthenticationException:
            log.info("%s: authentication failed for %s", target, credential.label)
            failures.append(credential.label)
        except NetmikoTimeoutException as exc:
            raise SessionError(Status.TIMEOUT, _first_line(exc)) from exc
        except paramiko.SSHException as exc:
            raise SessionError(Status.ERROR, f"SSH negotiation failed: {exc}") from exc
        except OSError as exc:
            raise SessionError(Status.UNREACHABLE, str(exc)) from exc
    raise SessionError(Status.AUTH_FAILED, f"authentication failed ({', '.join(failures)})")


def detect(conn: BaseConnection, target: Target | str = "") -> type[Driver]:
    """Identify the platform on a raw (terminal_server) connection."""
    initial = _read_until_prompt(conn, send_return=True, timeout=15)
    log.debug("%s: initial buffer %r", target, initial[-300:])

    probes: list[str] = []
    for driver in DRIVERS:
        probes.extend(cmd for cmd in driver.detect if cmd not in probes)

    seen = []
    for command in probes:
        output = _probe(conn, command)
        seen.append(f"{command!r}: {_first_line(output) or '<no output>'}")
        for driver in DRIVERS:
            patterns = driver.detect.get(command, [])
            if any(re.search(p, output, re.MULTILINE | re.IGNORECASE) for p in patterns):
                return driver
    raise SessionError(Status.UNSUPPORTED, "platform not recognised; " + "; ".join(seen))


def _probe(conn: BaseConnection, command: str, timeout: float = 15) -> str:
    conn.write_channel(command + conn.RETURN)
    output = _read_until_prompt(conn, timeout=timeout)
    lines = output.split("\n")
    # Drop the echoed command and the trailing prompt.
    if lines and command in lines[0]:
        lines = lines[1:]
    if lines and _PROMPT.match(lines[-1].rstrip()):
        lines = lines[:-1]
    return "\n".join(lines).strip("\n")


def _read_until_prompt(
    conn: BaseConnection, timeout: float, send_return: bool = False, settle: float = 0.4
) -> str:
    """Read until a prompt-like last line has been idle for ``settle`` seconds.

    Pagers are quit with "q" (the first page is enough for detection), and the AOS-S
    "Press any key to continue" banner is acknowledged.
    """
    if send_return:
        conn.write_channel(conn.RETURN)
    buffer = ""
    deadline = time.monotonic() + timeout
    last_data = time.monotonic()
    while time.monotonic() < deadline:
        chunk = conn.read_channel()
        now = time.monotonic()
        if chunk:
            buffer += chunk
            last_data = now
            tail = clean(buffer)[-300:]
            last_line = tail.rstrip(" \n").rsplit("\n", 1)[-1]
            if _ANY_KEY.search(last_line):
                conn.write_channel(conn.RETURN)
            elif _PAGER.search(last_line):
                conn.write_channel("q")
            continue
        text = clean(buffer)
        last_line = text.rstrip("\n").rsplit("\n", 1)[-1].rstrip()
        if text and now - last_data >= settle and _PROMPT.match(last_line):
            return text
        time.sleep(0.05)
    return clean(buffer)


def _remote_version(conn: BaseConnection) -> str:
    try:
        return conn.remote_conn.transport.remote_version  # type: ignore[union-attr]
    except AttributeError:
        return ""


def _safe_disconnect(conn: BaseConnection) -> None:
    with contextlib.suppress(Exception):
        conn.disconnect()


def _first_line(value: object) -> str:
    return next((line.strip() for line in str(value).splitlines() if line.strip()), "")
