"""HPE Aruba AOS-CX (4100i/6xxx/8xxx) and AOS-S / ProCurve (2530/2930/3810/5400R)."""

from __future__ import annotations

import re
from typing import Any

from sshawk.drivers.base import Driver, neighbors_from_rows, parse_textfsm, search
from sshawk.models import StackMember

_MAC = (
    r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}"  # 88:3a:30:aa:bb:cc
    r"|[0-9a-fA-F]{6}-[0-9a-fA-F]{6}"  # b05ada-123456
    r"|[0-9a-fA-F]{4}(?:[.:][0-9a-fA-F]{4}){2}"  # 9c8c.d8aa.bb00
)

# AOS-CX show vsf:   " 1   88:3a:30:aa:bb:cc    JL659A               Master"
_CX_VSF_ROW = re.compile(
    rf"^\s*(?P<slot>\d+)\s+(?P<mac>{_MAC})\s+(?P<model>\S+)\s+(?P<status>\S+)", re.MULTILINE
)
# AOS-S show stacking / show vsf:
#   " 1   b05ada-123456     HP J9729A 2920-48G-POE+ Switch          128 Commander"
_AOSS_MEMBER_ROW = re.compile(
    rf"^\s*(?P<slot>\d+)\s+(?P<mac>{_MAC})\s+(?P<model>.+?)\s+(?P<priority>\d+)\s+(?P<status>\S+)",
    re.MULTILINE,
)

_ROLES = {
    "master": "active",
    "commander": "active",
    "conductor": "active",
    "standby": "standby",
    "member": "member",
}


def parse_aoscx_show_system(text: str) -> dict[str, Any]:
    return {
        "hostname": search(r"^Hostname\s*:\s*(\S+)", text),
        "model": search(r"^Product Name\s*:\s*(.+?)\s*$", text),
        "serial": search(r"^Chassis Serial Nbr\s*:\s*(\S+)", text),
        "mac": search(r"^Base MAC Address\s*:\s*(\S+)", text).lower(),
        "version": search(r"^(?:ArubaOS-CX|AOS-CX) Version\s*:\s*(\S+)", text)
        or search(r"^System Description\s*:\s*(\S+)", text),
        "uptime": search(r"^Up Time\s*:\s*(.+?)\s*$", text),
    }


def parse_aoscx_show_version(text: str) -> dict[str, str]:
    return {
        "version": search(r"^Version\s*:\s*(\S+)", text),
        "active_image": search(r"^Active Image\s*:\s*(\S+)", text),
    }


def parse_aoscx_show_vsf(text: str) -> list[StackMember]:
    return [
        StackMember(
            slot=m["slot"],
            role=_ROLES.get(m["status"].lower(), m["status"].lower()),
            model=m["model"],
            mac=m["mac"].lower(),
        )
        for m in _CX_VSF_ROW.finditer(text)
    ]


class ArubaAosCx(Driver):
    device_type = "aruba_aoscx"
    vendor = "HPE Aruba"
    os_name = "AOS-CX"
    detect = {"show version": [r"ArubaOS-CX", r"\bAOS-CX\b"]}

    def collect_inventory(self) -> None:
        info = self.info
        data = parse_aoscx_show_system(self.run("show system"))
        for key in ("hostname", "model", "serial", "mac", "version", "uptime"):
            if data[key]:
                setattr(info, key, data[key])
        if output := self.try_run("show version"):
            version = parse_aoscx_show_version(output)
            info.version = version["version"] or info.version
            if version["active_image"]:
                info.extra["active_image"] = version["active_image"]

        members = []
        if output := self.try_run("show vsf"):
            members = parse_aoscx_show_vsf(output)
        if members:
            for member in members:
                member.version = info.version
                if member.mac == info.mac:
                    member.serial = info.serial
        else:
            members = [
                StackMember(
                    slot="1",
                    role="active",
                    model=info.model,
                    serial=info.serial,
                    version=info.version,
                    mac=info.mac,
                )
            ]
        info.members = members

    def collect_neighbors(self) -> None:
        if output := self.try_run("show lldp neighbor-info detail"):
            rows = parse_textfsm("aruba_aoscx_show_lldp_neighbors-info_detail", output)
            self.info.neighbors.extend(neighbors_from_rows("lldp", rows))


def parse_aoss_show_system(text: str) -> dict[str, Any]:
    return {
        "hostname": search(r"System Name\s*:\s*(\S+)", text),
        "version": search(r"Software revision\s*:\s*(\S+)", text),
        "serial": search(r"Serial Number\s*:\s*(\S+)", text),
        "mac": search(r"Base MAC Addr\s*:\s*(\S+)", text).lower(),
        "uptime": search(r"Up Time\s*:\s*(.+?)(?:\s{2,}|\s*$)", text),
        "rom": search(r"ROM Version\s*:\s*(\S+)", text),
    }


def parse_aoss_show_modules(text: str) -> dict[str, str]:
    """``Chassis: 2930F-24G-PoE+-4SFP+ JL255A       Serial Number:   CN83HKX0AB``."""
    chassis = search(r"^\s*Chassis:\s*(.+?)\s{2,}Serial Number", text) or search(
        r"^\s*Chassis:\s*(.+?)\s*$", text
    )
    return {"model": chassis, "serial": search(r"^\s*Chassis:.*Serial Number:\s*(\S+)", text)}


def parse_aoss_members(text: str) -> list[StackMember]:
    return [
        StackMember(
            slot=m["slot"],
            role=_ROLES.get(m["status"].lower(), m["status"].lower()),
            model=re.sub(r"^(?:HP|HPE|Aruba)\s+", "", m["model"]),
            mac=m["mac"].lower(),
        )
        for m in _AOSS_MEMBER_ROW.finditer(text)
    ]


class ArubaAosS(Driver):
    device_type = "hp_procurve"
    vendor = "HPE Aruba"
    os_name = "AOS-S"
    detect = {"show version": [r"Image stamp:[\s\S]*Boot Image:"]}

    def collect_inventory(self) -> None:
        info = self.info
        data = parse_aoss_show_system(self.run("show system"))
        for key in ("hostname", "version", "serial", "mac", "uptime"):
            if data[key]:
                setattr(info, key, data[key])
        if data["rom"]:
            info.extra["rom_version"] = data["rom"]

        if output := self.try_run("show modules"):
            modules = parse_aoss_show_modules(output)
            info.model = modules["model"] or info.model
            info.serial = info.serial or modules["serial"]

        members = []
        for command in ("show stacking", "show vsf"):
            output = self.try_run(command)
            if output and (members := parse_aoss_members(output)):
                info.extra["stack_type"] = command.split()[-1]
                break
        if members:
            for member in members:
                member.version = info.version
                if member.role == "active":
                    member.serial = info.serial
        else:
            members = [
                StackMember(
                    slot="1",
                    role="active",
                    model=info.model,
                    serial=info.serial,
                    version=info.version,
                    mac=info.mac,
                )
            ]
        info.members = members

    def collect_neighbors(self) -> None:
        if output := self.try_run("show lldp info remote-device detail"):
            rows = parse_textfsm("hp_procurve_show_lldp_info_remote-device_detail", output)
            self.info.neighbors.extend(neighbors_from_rows("lldp", rows))
        if output := self.try_run("show cdp neighbors detail"):
            rows = parse_textfsm("hp_procurve_show_cdp_neighbors_detail", output)
            self.info.neighbors.extend(neighbors_from_rows("cdp", rows))
