"""Driver base class and parsing helpers shared by all vendors."""

from __future__ import annotations

import logging
import re
from functools import cache
from importlib import resources
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar, Protocol

import textfsm

from sshawk.models import DeviceInfo, Neighbor

if TYPE_CHECKING:
    from collections.abc import Iterable

log = logging.getLogger(__name__)

# Output fragments that mean "the device did not accept this command".
COMMAND_ERRORS = re.compile(
    r"% ?Invalid input|% ?Unrecognized command|% ?Unknown command|% ?Incomplete command"
    r"|Error: ?Unrecognized command|Error: ?Wrong parameter|Error: ?Incomplete command"
    r"|^Invalid input:|% ?Invalid command|% ?Ambiguous command|Syntax error|command not found"
    r"|% (?:CDP|LLDP) is not enabled|LLDP is not enabled",
    re.IGNORECASE | re.MULTILINE,
)


_MAC_LIKE = re.compile(
    r"^(?:[0-9a-fA-F]{2}[:\- ]?){5}[0-9a-fA-F]{2}$|^(?:[0-9a-fA-F]{4}[.\-]){2}[0-9a-fA-F]{4}$"
)


class CommandError(RuntimeError):
    """The device rejected a command (unknown command, feature disabled, ...)."""


class Connection(Protocol):
    """The subset of a netmiko connection that drivers use (eases testing)."""

    base_prompt: str

    def send_command(self, command_string: str, **kwargs: Any) -> str: ...


class Driver:
    """Collects data from one device type.

    Subclasses set the class attributes and implement :meth:`collect_inventory`, and
    optionally :meth:`collect_neighbors`. Parsing lives in module-level functions so it
    can be tested against captured outputs without a device.
    """

    device_type: ClassVar[str]  # netmiko device_type
    vendor: ClassVar[str]
    os_name: ClassVar[str]
    # probe command -> regexes; a match on the probe output selects this driver
    detect: ClassVar[dict[str, list[str]]] = {}

    def __init__(self, conn: Connection, info: DeviceInfo, raw: dict[str, str] | None = None):
        self.conn = conn
        self.info = info
        self.raw = raw if raw is not None else {}

    def run(self, command: str, read_timeout: float = 60) -> str:
        """Run a show command and return its output; raise CommandError if rejected."""
        output = self.conn.send_command(command, read_timeout=read_timeout)
        self.raw[command] = output
        if COMMAND_ERRORS.search(output[:500]):
            first_line = next((line for line in output.splitlines() if line.strip()), "")
            raise CommandError(f"{command!r} rejected: {first_line.strip()}")
        return output

    def try_run(self, command: str, read_timeout: float = 60) -> str | None:
        """Like :meth:`run`, but return None instead of raising for rejected commands."""
        try:
            return self.run(command, read_timeout)
        except CommandError as exc:
            log.debug("%s: %s", self.info.host, exc)
            return None

    def collect(self, neighbors: bool = False) -> None:
        self.info.vendor = self.vendor
        self.info.os = self.info.os or self.os_name
        self.info.device_type = self.device_type
        self.collect_inventory()
        if not self.info.hostname:
            self.info.hostname = prompt_hostname(getattr(self.conn, "base_prompt", ""))
        if neighbors:
            try:
                self.collect_neighbors()
            except Exception as exc:  # noqa: BLE001 - inventory is still useful without neighbors
                log.debug("%s: neighbor collection failed", self.info.host, exc_info=True)
                self.info.warnings.append(f"neighbor collection failed: {exc}")

    def collect_inventory(self) -> None:
        raise NotImplementedError

    def collect_neighbors(self) -> None:
        self.info.warnings.append(f"neighbor collection not implemented for {self.device_type}")


def prompt_hostname(base_prompt: str) -> str:
    """Derive a hostname from a netmiko base prompt (``<sw01>``, ``sw01:1``, ``* sw01.3``)."""
    name = base_prompt.strip().lstrip("*").strip().strip("<>[]")
    name = re.sub(r"[:.]\d+$", "", name)  # VOSS "host:1", EXOS "host.12"
    return name


def search(pattern: str, text: str, flags: int = re.MULTILINE, group: int | str = 1) -> str:
    """Return a stripped regex group, or "" if there is no match."""
    match = re.search(pattern, text, flags)
    return match.group(group).strip() if match else ""


@cache
def _template_path(name: str) -> Path:
    own = resources.files("sshawk") / "templates" / f"{name}.textfsm"
    if own.is_file():
        return Path(str(own))
    ntc = resources.files("ntc_templates") / "templates" / f"{name}.textfsm"
    if ntc.is_file():
        return Path(str(ntc))
    raise FileNotFoundError(f"TextFSM template {name!r} not found")


def parse_textfsm(template: str, text: str) -> list[dict[str, Any]]:
    """Parse text with a named template (sshawk's own first, then ntc-templates).

    Returns rows as dicts with lower-case keys, like ntc_templates.parse.parse_output.
    """
    with _template_path(template).open(encoding="utf-8") as handle:
        fsm = textfsm.TextFSM(handle)
    rows = fsm.ParseText(text)
    keys = [h.lower() for h in fsm.header]
    return [dict(zip(keys, row, strict=True)) for row in rows]


def first(value: Any) -> str:
    """Normalise TextFSM List values: first element of a list, or the value itself."""
    if isinstance(value, list):
        value = value[0] if value else ""
    return str(value or "").strip()


def neighbors_from_rows(protocol: str, rows: Iterable[dict[str, Any]]) -> list[Neighbor]:
    """Build Neighbor objects from ntc-style rows (shared field names across templates)."""
    result = []
    for row in rows:
        # Templates disagree: LLDP "port id" is the interface name (or a MAC for hosts),
        # NEIGHBOR_INTERFACE is the port description there but the port id for CDP.
        port_id = first(row.get("neighbor_port_id"))
        if not port_id or _MAC_LIKE.match(port_id):
            port_id = first(row.get("neighbor_interface")) or port_id
        result.append(
            Neighbor(
                protocol=protocol,
                local_interface=first(row.get("local_interface")),
                remote_hostname=first(row.get("neighbor_name")),
                remote_interface=port_id,
                remote_ip=first(row.get("mgmt_address")),
                remote_platform=first(row.get("platform")),
                remote_description=" ".join(
                    row["neighbor_description"]
                    if isinstance(row.get("neighbor_description"), list)
                    else [first(row.get("neighbor_description"))]
                ).strip(),
                remote_chassis_id=first(row.get("chassis_id")),
            )
        )
    return result
