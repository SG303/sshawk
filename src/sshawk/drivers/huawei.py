"""Huawei campus switches: VRP V200 (S5700/S6700 ...) and YunShan OS V600 (S5735/S6730 ...)."""

from __future__ import annotations

import re
from typing import Any

from sshawk.drivers.base import Driver, neighbors_from_rows, parse_textfsm, search
from sshawk.models import StackMember

# "(S5720 V200R019C10SPC500)" or "(V200R019C10SPC500)"
_PRODUCT_VERSION = re.compile(r"\((?:[\w-]+\s+)?(V\d{3}R\d{3}\w*)\)")
_STACK_ROW = re.compile(
    r"^\s*(?P<slot>\d+)\s+(?P<role>Master|Standby|Slave|Backup|Member)\s+"
    r"(?P<mac>[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4})\s+(?P<priority>\d+)\s+(?P<model>\S+)",
    re.IGNORECASE | re.MULTILINE,
)
_ESN_ROW = re.compile(
    r"^\s*ESN of (?:slot|chassis)\s+(\S+?)\s*:\s*(\S+)", re.IGNORECASE | re.MULTILINE
)
# display device manufacture-info: "0     -    2102352168P0K9000123   2019-08-06"
_MANUFACTURE_ROW = re.compile(
    r"^\s*(\d+)\s+(?:-|\S+)\s+([0-9A-Z]{12,})\s+\d{4}-\d{2}-\d{2}", re.MULTILINE
)


def parse_display_version(text: str) -> dict[str, Any]:
    os_name = "YunShan" if re.search(r"YunShan", text, re.IGNORECASE) else "VRP"
    version = ""
    if match := _PRODUCT_VERSION.search(text):
        version = match.group(1)
    model, uptime = "", ""
    if match := re.search(
        r"^(?:HUAWEI|Huawei|Quidway)[ \t]+(\S+)(?:[ \t]+\S+)*?[ \t]+uptime is (.+)$",
        text,
        re.MULTILINE,
    ):
        model, uptime = match.group(1), match.group(2).strip()
    return {
        "os": os_name,
        "version": version,
        "os_version": search(
            r"(?:software, Version|^Version)\s+([\d.]+)", text, re.MULTILINE | re.IGNORECASE
        ),
        "model": model,
        "uptime": uptime,
        "patch": search(r"^Patch [Vv]ersion\s*:\s*(\S+)", text),
    }


def parse_display_esn(text: str) -> dict[str, str]:
    """Map slot -> ESN."""
    return {slot: esn for slot, esn in _ESN_ROW.findall(text)}


def parse_manufacture_info(text: str) -> dict[str, str]:
    return {slot: esn for slot, esn in _MANUFACTURE_ROW.findall(text)}


def parse_display_stack(text: str) -> list[StackMember]:
    members = []
    for match in _STACK_ROW.finditer(text):
        role = match["role"].lower()
        members.append(
            StackMember(
                slot=match["slot"],
                role={"master": "active", "slave": "standby", "backup": "standby"}.get(role, role),
                model=match["model"],
                mac=match["mac"].lower(),
            )
        )
    return members


class HuaweiVrp(Driver):
    device_type = "huawei"
    vendor = "Huawei"
    os_name = "VRP"
    detect = {
        "display version": [
            r"Huawei Versatile Routing Platform",
            r"Huawei YunShan OS",
            r"VRP \(R\) software",
        ]
    }

    def collect_inventory(self) -> None:
        info = self.info
        data = parse_display_version(self.run("display version"))
        for key in ("os", "version", "model", "uptime"):
            if data[key]:
                setattr(info, key, data[key])
        for key in ("os_version", "patch"):
            if data[key]:
                info.extra[key] = data[key]

        serials = {}
        if output := self.try_run("display esn"):
            serials = parse_display_esn(output)
        if not serials and (output := self.try_run("display device manufacture-info")):
            serials = parse_manufacture_info(output)

        members = []
        if output := self.try_run("display stack"):
            members = parse_display_stack(output)
        if not members:
            slot = next(iter(serials), "0")
            members = [StackMember(slot=slot, role="active", model=info.model)]
        for member in members:
            member.serial = serials.get(member.slot, member.serial)
            member.version = member.version or info.version
        info.members = members

        active = next((m for m in members if m.role == "active"), members[0])
        info.serial = active.serial or next(iter(serials.values()), "")
        info.mac = active.mac
        info.model = info.model or active.model

    def collect_neighbors(self) -> None:
        if output := self.try_run("display lldp neighbor"):
            rows = parse_textfsm("huawei_vrp_display_lldp_neighbor", output)
            self.info.neighbors.extend(neighbors_from_rows("lldp", rows))
