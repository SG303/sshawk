"""Cisco IOS and IOS-XE (Catalyst switches, ISR/ASR routers, C9800 WLC)."""

from __future__ import annotations

import re
from typing import Any

from sshawk.drivers.base import Driver, neighbors_from_rows, parse_textfsm, search
from sshawk.models import StackMember

_MEMBER_ROW = re.compile(
    r"^(?P<active>\*)?\s*(?P<slot>\d+)\s+(?P<ports>\d+)\s+(?P<model>\S+)\s+(?P<version>\S+)"
    r"\s+(?P<image>\S+)",
)
_MEMBER_SECTION = re.compile(r"^Switch\s+0*(\d+)\s*\n-{3,}\s*$", re.MULTILINE)


def parse_show_version(text: str) -> dict[str, Any]:
    is_xe = bool(re.search(r"Cisco IOS[ -]XE Software", text))
    version = ""
    if is_xe:
        version = search(r"^Cisco IOS XE Software, Version (\S+)", text)
    version = version or search(r"Cisco IOS.*?Software.*?, Version ([^\s,]+)", text)

    hostname, uptime = "", ""
    if match := re.search(r"^(\S+) uptime is (.+)$", text, re.MULTILINE):
        hostname, uptime = match.group(1), match.group(2).strip()

    model = search(r"^Model [Nn]umber\s*:\s*(\S+)", text) or search(
        r"^[Cc]isco (\S+) \(.*\) processor", text
    )
    serial = search(r"^System [Ss]erial [Nn]umber\s*:\s*(\S+)", text) or search(
        r"^Processor board ID (\S+)", text
    )
    mac = search(r"^Base [Ee]thernet MAC [Aa]ddress\s*:\s*(\S+)", text)

    members = _parse_members(text, serial, mac)
    if members:
        # Prefer the active member's model; a standalone switch also has a table of one row.
        active = next((m for m in members if m.role == "active"), members[0])
        model = model or active.model

    return {
        "os": "IOS-XE" if is_xe else "IOS",
        "version": version,
        "hostname": hostname,
        "uptime": uptime,
        "model": model,
        "serial": serial,
        "mac": mac,
        "members": members,
        "image": search(r'^System image file is "([^"]+)"', text),
        "reload_reason": search(r"^Last reload reason:\s*(.+)$", text),
    }


def _parse_members(text: str, first_serial: str, first_mac: str) -> list[StackMember]:
    members: dict[str, StackMember] = {}
    table = re.search(
        r"^Switch\s+Ports\s+Model\s+SW Version.*?\n[- ]+\n(.*?)(?:\n\s*\n|\Z)",
        text,
        re.MULTILINE | re.DOTALL,
    )
    if table:
        for line in table.group(1).splitlines():
            if match := _MEMBER_ROW.match(line):
                members[match["slot"]] = StackMember(
                    slot=match["slot"],
                    role="active" if match["active"] else "member",
                    model=match["model"],
                    version=match["version"],
                )

    # Serial/MAC of the first member are in the main body, others in "Switch 0N" sections.
    sections = _MEMBER_SECTION.split(text)
    details = {"": sections[0]}
    for index in range(1, len(sections) - 1, 2):
        details[sections[index]] = sections[index + 1]
    for slot, member in members.items():
        body = details.get(slot)
        if body is None:
            if member.role != "active" and len(members) > 1:
                continue
            member.serial, member.mac = first_serial, first_mac
            continue
        member.serial = search(r"^\s*System [Ss]erial [Nn]umber\s*:\s*(\S+)", body)
        member.mac = search(r"^\s*Base [Ee]thernet MAC [Aa]ddress\s*:\s*(\S+)", body)
        member.model = search(r"^\s*Model [Nn]umber\s*:\s*(\S+)", body) or member.model
    return list(members.values())


def parse_show_inventory(text: str) -> list[dict[str, str]]:
    return parse_textfsm("cisco_ios_show_inventory", text)


class CiscoIos(Driver):
    device_type = "cisco_ios"
    vendor = "Cisco"
    os_name = "IOS"
    detect = {
        "show version": [
            r"Cisco IOS[ -]XE Software",
            r"Cisco IOS Software",
            r"Cisco Internetwork Operating System Software",
        ]
    }

    def collect_inventory(self) -> None:
        info = self.info
        data = parse_show_version(self.run("show version"))
        for key in ("os", "version", "hostname", "uptime", "model", "serial", "mac", "members"):
            if data[key]:
                setattr(info, key, data[key])
        for key in ("image", "reload_reason"):
            if data[key]:
                info.extra[key] = data[key]

        output = self.try_run("show inventory")
        if output:
            entries = parse_show_inventory(output)
            info.extra["inventory"] = entries
            # Routers: the chassis serial (show inventory) differs from the processor board ID.
            if entries and not info.members and entries[0].get("sn"):
                info.serial = entries[0]["sn"]
                info.model = entries[0].get("pid") or info.model

        if not info.members and (info.model or info.serial):
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
        if output := self.try_run("show cdp neighbors detail"):
            rows = parse_textfsm("cisco_ios_show_cdp_neighbors_detail", output)
            self.info.neighbors.extend(neighbors_from_rows("cdp", rows))
        if output := self.try_run("show lldp neighbors detail"):
            rows = parse_textfsm("cisco_ios_show_lldp_neighbors_detail", output)
            self.info.neighbors.extend(neighbors_from_rows("lldp", rows))
