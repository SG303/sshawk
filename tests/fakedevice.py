"""A fake SSH network device for end-to-end tests.

Each FakeDevice serves canned command outputs from ``tests/fixtures/devices/<name>/``
behind a vendor-flavoured CLI: prompt style, pager, error message, paging-disable
command, AOS-S "press any key" banner and Cisco enable mode.
"""

from __future__ import annotations

import logging
import socket
import threading
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

import paramiko

FIXTURES = Path(__file__).parent / "fixtures" / "devices"
PAGE_LINES = 20

# The server side logs every port check (connect + close) as an error; not interesting here.
logging.getLogger("paramiko.transport").setLevel(logging.CRITICAL)


@dataclass
class Profile:
    prompt: str  # format string with {host}, {n} (EXOS command counter) and {mode}
    error: str
    pager: str
    no_paging: tuple[str, ...]
    banner: str = ""
    any_key: bool = False


PROFILES = {
    "cisco_ios": Profile(
        "{host}{mode}",
        "% Invalid input detected at '^' marker.",
        " --More-- ",
        ("terminal length 0",),
    ),
    "huawei": Profile(
        "<{host}>",
        "Error: Unrecognized command found at '^' position.",
        "  ---- More ----",
        ("screen-length 0 temporary",),
        banner="Info: The max number of VTY users is 15.\r\n",
    ),
    "extreme_exos": Profile(
        "{host}.{n} # ",
        "%% Invalid input detected at '^' marker.",
        "Press <SPACE> to continue or <Q> to quit:",
        ("disable clipaging",),
    ),
    "extreme_vsp": Profile(
        "{host}:1>",
        "% Invalid input detected at '^' marker.",
        "--More-- (q = quit)",
        ("terminal more disable",),
    ),
    "aruba_aoscx": Profile(
        "{host}# ",
        "Invalid input: {cmd}",
        "-- MORE --, next page: Space, next line: Enter, quit: q",
        ("no page",),
    ),
    "hp_procurve": Profile(
        "{host}# ",
        "Invalid input: {cmd}",
        "-- MORE --, next page: Space, next line: Enter, quit: Control-C",
        ("no page",),
        banner="\x1b[2J\x1b[?7l\x1b[3;23r\x1b[?6l\x1b[1;1H\x1b[?25l\x1b[1;1H"
        "HPE Networking 2930F-24G-4SFP+ Switch\r\nSoftware revision WC.16.10.0012"
        "\r\n\r\n(C) Copyright 2020 Hewlett Packard Enterprise Development LP"
        "\r\n\r\n",
        any_key=True,
    ),
}


@dataclass
class DeviceSpec:
    name: str
    platform: str
    hostname: str
    username: str = "admin"
    password: str = "admin"
    secret: str = ""  # Cisco: start in user exec, "enable" needs this
    commands: dict[str, str] = field(default_factory=dict)
    expected: dict = field(default_factory=dict)

    @classmethod
    def load(cls, name: str) -> DeviceSpec:
        directory = FIXTURES / name
        meta = tomllib.loads((directory / "device.toml").read_text(encoding="utf-8"))
        commands = {}
        for path in sorted((directory / "commands").glob("*.txt")):
            commands[path.stem.replace("_", " ")] = path.read_text(encoding="utf-8")
        return cls(name=name, commands=commands, expected=meta.pop("expected", {}), **meta)


def all_specs() -> list[DeviceSpec]:
    return [DeviceSpec.load(p.name) for p in sorted(FIXTURES.iterdir()) if p.is_dir()]


class FakeDevice:
    _host_key: paramiko.PKey | None = None

    def __init__(self, spec: DeviceSpec, address: str = "127.0.0.1", port: int = 0):
        self.spec = spec
        self.profile = PROFILES[spec.platform]
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((address, port))
        self.sock.listen(16)
        self.address, self.port = self.sock.getsockname()
        self.logins: list[str] = []  # usernames of successful logins
        self.failed_logins: list[str] = []
        self.received: list[str] = []  # every command line typed
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    @classmethod
    def host_key(cls) -> paramiko.PKey:
        if cls._host_key is None:
            cls._host_key = paramiko.RSAKey.generate(1024)
        return cls._host_key

    @property
    def target(self) -> str:
        return f"{self.address}:{self.port}"

    def start(self) -> FakeDevice:
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        self.sock.close()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                client, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(client,), daemon=True).start()

    def _handle(self, client: socket.socket) -> None:
        transport = paramiko.Transport(client)
        transport.add_server_key(self.host_key())
        server = _Server(self)
        try:
            transport.start_server(server=server)
            channel = transport.accept(20)
            if channel is None:
                return
            server.shell_ready.wait(10)
            _Cli(self, channel, server.username).run()
        except (EOFError, OSError, paramiko.SSHException):
            pass
        finally:
            transport.close()


class _Server(paramiko.ServerInterface):
    def __init__(self, device: FakeDevice):
        self.device = device
        self.username = ""
        self.shell_ready = threading.Event()

    def check_auth_password(self, username: str, password: str) -> int:
        spec = self.device.spec
        if username == spec.username and password == spec.password:
            self.username = username
            self.device.logins.append(username)
            return paramiko.AUTH_SUCCESSFUL
        self.device.failed_logins.append(username)
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username: str) -> str:
        return "password"

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, *args: object) -> bool:
        return True

    def check_channel_shell_request(self, channel: paramiko.Channel) -> bool:
        self.shell_ready.set()
        return True


class _Cli:
    def __init__(self, device: FakeDevice, channel: paramiko.Channel, username: str):
        self.device = device
        self.spec = device.spec
        self.profile = device.profile
        self.channel = channel
        self.paging = True
        self.privileged = not self.spec.secret
        self.counter = 1

    def prompt(self) -> str:
        mode = "#" if self.privileged else ">"
        return self.profile.prompt.format(host=self.spec.hostname, n=self.counter, mode=mode)

    def send(self, text: str) -> None:
        self.channel.sendall(text.replace("\r\n", "\n").replace("\n", "\r\n").encode())

    def read_line(self, echo: bool = True) -> str | None:
        line = ""
        while True:
            data = self.channel.recv(1024)
            if not data:
                return None
            for char in data.decode(errors="replace"):
                if char in "\r\n":
                    if char == "\n" and self._skip_lf:
                        self._skip_lf = False
                        continue
                    self._skip_lf = char == "\r"
                    if echo:
                        self.send("\n")
                    return line
                self._skip_lf = False
                if char in "\x08\x7f":
                    line = line[:-1]
                    continue
                line += char
                if echo:
                    self.send(char)

    _skip_lf = False

    def read_key(self) -> str | None:
        data = self.channel.recv(16)
        if not data:
            return None
        if data in (b"\r", b"\n", b"\r\n"):
            self._skip_lf = data == b"\r"
        return data.decode(errors="replace")[:1]

    def run(self) -> None:
        if self.profile.banner:
            self.send(self.profile.banner)
        if self.profile.any_key:
            self.send("Press any key to continue\n")
            if self.read_key() is None:
                return
            self.send("\n")
        self.send(self.prompt())
        while True:
            line = self.read_line()
            if line is None:
                return
            command = line.strip()
            if command:
                self.device.received.append(command)
            if command in ("exit", "quit", "logout"):
                self.channel.close()
                return
            if not self.handle(command):
                return
            if command:
                self.counter += 1
            self.send(self.prompt())

    def handle(self, command: str) -> bool:
        if not command:
            return True
        if command in self.profile.no_paging:
            self.paging = False
            return True
        if command == "enable" and self.spec.platform == "cisco_ios":
            if self.privileged:
                return True
            self.send("Password: ")
            secret = self.read_line(echo=False)
            if secret is None:
                return False
            self.send("\n")
            if secret == self.spec.secret:
                self.privileged = True
            else:
                self.send("% Access denied\n")
            return True
        output = self.spec.commands.get(command)
        if output is None:
            if _is_harmless(command):
                return True
            self.send(self.profile.error.format(cmd=command) + "\n")
            return True
        return self.page(output.rstrip("\n") + "\n")

    def page(self, output: str) -> bool:
        lines = output.splitlines(keepends=True)
        if not self.paging or len(lines) <= PAGE_LINES:
            self.send(output)
            return True
        for start in range(0, len(lines), PAGE_LINES):
            self.send("".join(lines[start : start + PAGE_LINES]))
            if start + PAGE_LINES >= len(lines):
                break
            self.send(self.profile.pager)
            key = self.read_key()
            if key is None:
                return False
            self.send("\r" + " " * len(self.profile.pager) + "\r")
            if key not in (" ", "\r", "\n"):
                self.send("\n")
                break
        return True


def _is_harmless(command: str) -> bool:
    """Session setup commands netmiko sends that we accept silently."""
    return command.startswith(("terminal ", "screen-width", "disable cli prompting"))
