"""Extreme Networks ExtremeXOS (X4xx/X6xx/5xxx) and VOSS (VSP/5xxx Fabric Engine)."""

from __future__ import annotations

import re
from typing import Any

from sshawk.drivers.base import Driver, search
from sshawk.models import Neighbor, StackMember

# show version: "Switch      : 800616-00-06 1918N-41234 Rev 6.0 BootROM: 2.0.1.8    IMG: 31.7.1.4"
#               "Slot-2      : 800616-00-06 1918N-41235 Rev 6.0 BootROM: 2.0.1.8    IMG: 31.7.1.4"
_EXOS_UNIT = re.compile(
    r"^(?P<unit>Switch|Slot-\d+)\s*:\s*(?P<part>\S+)\s+(?P<serial>\S+)\s+Rev\s+\S+"
    r"(?:.*?IMG:\s*(?P<version>\S+))?",
    re.MULTILINE,
)
# show stacking: "*00:04:96:9b:a1:b2  1     Active       Master   CA-"
_EXOS_STACK_ROW = re.compile(
    r"^\s*\*?\s*(?P<mac>[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\s+(?P<slot>\d+)\s+(?P<state>\S+)"
    r"\s+(?P<role>\S+)",
    re.MULTILINE,
)
# show slot: "Slot-1   X440G2-48p-10G4      X440G2-48p-10G4      Operational   54  M"
_EXOS_SLOT_ROW = re.compile(r"^Slot-(?P<slot>\d+)\s+(?P<type>\S+)", re.MULTILINE)


def parse_exos_show_switch(text: str) -> dict[str, Any]:
    model = search(r"^System Type:\s*(\S+)", text)
    return {
        "hostname": search(r"^SysName:\s*(\S+)", text),
        "model": model,
        "stacked": "(Stack)" in search(r"^(System Type:.*)$", text),
        "mac": search(r"^System MAC:\s*(\S+)", text).lower(),
        "uptime": search(r"^System UpTime:\s*(.+?)\s*$", text),
        "image_booted": search(r"^Image Booted:\s*(\S+)", text),
        "primary_version": search(r"^Primary ver:\s*(\S+)", text),
        "secondary_version": search(r"^Secondary ver:\s*(\S+)", text),
    }


def parse_exos_show_version(text: str) -> dict[str, Any]:
    units = []
    for match in _EXOS_UNIT.finditer(text):
        slot = "1" if match["unit"] == "Switch" else match["unit"].split("-", 1)[1]
        units.append(StackMember(slot=slot, serial=match["serial"], version=match["version"] or ""))
    return {
        "version": search(r"^Image\s*:\s*ExtremeXOS version (\S+)", text),
        "units": units,
    }


def parse_exos_show_stacking(text: str) -> dict[str, tuple[str, str]]:
    """Map slot -> (role, mac)."""
    roles = {"master": "active", "backup": "standby", "standby": "member"}
    return {
        m["slot"]: (roles.get(m["role"].lower(), m["role"].lower()), m["mac"].lower())
        for m in _EXOS_STACK_ROW.finditer(text)
    }


def parse_exos_lldp_detail(text: str) -> list[Neighbor]:
    neighbors = []
    for block in re.split(r"^LLDP Port ", text, flags=re.MULTILINE)[1:]:
        local = block.split(None, 1)[0]
        for neighbor_block in re.split(r"^\s*Neighbor:", block, flags=re.MULTILINE)[1:]:
            description = search(r'System Description:\s*"(.*?)"\\?\s*$', neighbor_block)
            # Long values continue on the next line as  "...."\  -> join them.
            if cont := re.search(r'System Description:\s*"(.*?)"\\\s*\n\s*"(.*?)"', neighbor_block):
                description = cont.group(1) + cont.group(2)
            neighbors.append(
                Neighbor(
                    protocol="lldp",
                    local_interface=local,
                    remote_hostname=search(r'System Name:\s*"(.*?)"', neighbor_block),
                    remote_interface=search(r'Port ID:\s*"?([^"\n]+)"?', neighbor_block),
                    remote_ip=search(r"Management Address\s*:\s*(\S+)", neighbor_block),
                    remote_description=description,
                    remote_chassis_id=search(r"Chassis ID\s*:\s*(\S+)", neighbor_block),
                )
            )
    return neighbors


class ExtremeExos(Driver):
    device_type = "extreme_exos"
    vendor = "Extreme"
    os_name = "EXOS"
    detect = {"show version": [r"ExtremeXOS", r"^Image\s*:\s*ExtremeXOS"]}

    def collect_inventory(self) -> None:
        info = self.info
        switch = parse_exos_show_switch(self.run("show switch"))
        for key in ("hostname", "model", "mac", "uptime"):
            if switch[key]:
                setattr(info, key, switch[key])
        for key in ("image_booted", "primary_version", "secondary_version"):
            if switch[key]:
                info.extra[key] = switch[key]

        version = parse_exos_show_version(self.run("show version"))
        info.version = version["version"] or switch["primary_version"]
        members = version["units"]

        if switch["stacked"] or len(members) > 1:
            if output := self.try_run("show stacking"):
                for slot, (role, mac) in parse_exos_show_stacking(output).items():
                    member = next((m for m in members if m.slot == slot), None)
                    if member is None:
                        member = StackMember(slot=slot)
                        members.append(member)
                    member.role, member.mac = role, mac
            if output := self.try_run("show slot"):
                types = {m["slot"]: m["type"] for m in _EXOS_SLOT_ROW.finditer(output)}
                for member in members:
                    member.model = types.get(member.slot, member.model)
            info.model = re.sub(r"\s*\(Stack\)", "", info.model)
        else:
            for member in members:
                member.role, member.model, member.mac = "active", info.model, info.mac

        for member in members:
            member.version = member.version or info.version
        info.members = members
        active = next((m for m in members if m.role == "active"), members[0] if members else None)
        if active:
            info.serial = active.serial

    def collect_neighbors(self) -> None:
        if output := self.try_run("show lldp neighbors detailed"):
            self.info.neighbors.extend(parse_exos_lldp_detail(output))


def parse_voss_sys_info(text: str) -> dict[str, Any]:
    descr = search(r"^\s*SysDescr\s*:\s*(.+?)\s*$", text)
    return {
        "hostname": search(r"^\s*SysName\s*:\s*(\S+)", text),
        "uptime": search(r"^\s*SysUpTime\s*:\s*(.+?)\s*$", text),
        "model": search(r"^\s*ModelName\s*:\s*(\S+)", text) or descr.split(" (")[0],
        "version": search(r"\(([\d.]+[^)]*)\)", descr),
        "serial": search(r"^\s*Serial#\s*:\s*(\S+)", text),
        "mac": search(r"^\s*Base MAC Addr\s*:\s*(\S+)", text).lower(),
    }


def parse_voss_lldp_neighbor(text: str) -> list[Neighbor]:
    neighbors = []
    for block in re.split(r"^Port:\s*", text, flags=re.MULTILINE)[1:]:
        neighbors.append(
            Neighbor(
                protocol="lldp",
                local_interface=block.split(None, 1)[0],
                remote_hostname=search(r"^\s*SysName\s*:\s*(.+?)\s*$", block),
                remote_interface=search(
                    r"^\s*PortId\s*:\s*(?:Interface name|Local|MAC Address|"
                    r"Interface alias)?\s*(\S+)\s*$",
                    block,
                ),
                remote_ip=search(r"^\s*Address\s*:\s*(\S+)", block),
                remote_description=search(r"^\s*SysDescr\s*:\s*(.+?)\s*$", block),
                remote_chassis_id=search(r"^\s*ChassisId\s*:\s*(?:MAC Address\s+)?(\S+)", block),
            )
        )
    return neighbors


class ExtremeVoss(Driver):
    device_type = "extreme_vsp"
    vendor = "Extreme"
    os_name = "VOSS"
    detect = {"show sys-info": [r"General Info\s*:[\s\S]*SysDescr\s*:"]}

    def collect_inventory(self) -> None:
        info = self.info
        data = parse_voss_sys_info(self.run("show sys-info"))
        for key in ("hostname", "uptime", "model", "version", "serial", "mac"):
            if data[key]:
                setattr(info, key, data[key])
        info.members = [
            StackMember(
                slot="1",
                role="active",
                model=info.model,
                serial=info.serial,
                version=info.version,
                mac=info.mac,
            )
        ]

    def collect_neighbors(self) -> None:
        if output := self.try_run("show lldp neighbor"):
            self.info.neighbors.extend(parse_voss_lldp_neighbor(output))
