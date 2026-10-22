"""Data model shared by drivers, scanner and exporters."""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class Status(StrEnum):
    OK = "ok"
    PARTIAL = "partial"  # connected, but some data could not be collected
    AUTH_FAILED = "auth_failed"
    UNREACHABLE = "unreachable"  # TCP port closed or filtered
    TIMEOUT = "timeout"
    UNSUPPORTED = "unsupported"  # logged in, but platform not recognised
    ERROR = "error"


@dataclass
class StackMember:
    """One chassis of a stack/VSF/IRF group, or the single chassis of a standalone switch."""

    slot: str = ""
    role: str = ""
    model: str = ""
    serial: str = ""
    version: str = ""
    mac: str = ""


@dataclass
class Neighbor:
    """A CDP/LLDP neighbor seen on one local interface."""

    protocol: str  # "cdp" or "lldp"
    local_interface: str = ""
    remote_hostname: str = ""
    remote_interface: str = ""
    remote_ip: str = ""
    remote_platform: str = ""
    remote_description: str = ""
    remote_chassis_id: str = ""


@dataclass
class DeviceInfo:
    """Everything sshawk knows about one scanned target."""

    host: str
    port: int = 22
    status: Status = Status.ERROR
    error: str = ""
    credential: str = ""  # name of the credential set that worked
    device_type: str = ""  # netmiko device_type used for the session
    vendor: str = ""
    os: str = ""
    hostname: str = ""
    model: str = ""
    serial: str = ""
    version: str = ""
    uptime: str = ""
    mac: str = ""
    members: list[StackMember] = field(default_factory=list)
    neighbors: list[Neighbor] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)
    discovered_via: str = ""  # "" for user-supplied targets, else "<host> (<protocol>)"
    collected_at: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat(timespec="seconds")
    )

    @property
    def ok(self) -> bool:
        return self.status in (Status.OK, Status.PARTIAL)

    @property
    def serials(self) -> list[str]:
        """All known serial numbers: the stack members' if any, else the device serial."""
        found = [m.serial for m in self.members if m.serial]
        if not found and self.serial:
            found = [self.serial]
        return found

    def to_dict(self) -> dict[str, Any]:
        data = dataclasses.asdict(self)
        data["status"] = str(self.status)
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DeviceInfo:
        data = dict(data)
        data["status"] = Status(data.get("status", Status.ERROR))
        data["members"] = [StackMember(**m) for m in data.get("members", [])]
        data["neighbors"] = [Neighbor(**n) for n in data.get("neighbors", [])]
        return cls(**data)

    def __repr__(self) -> str:
        parts = [f"host={self.host}", f"status={self.status}"]
        for name in ("hostname", "vendor", "model", "version"):
            if value := getattr(self, name):
                parts.append(f"{name}={value!r}")
        return f"<DeviceInfo {' '.join(parts)}>"
