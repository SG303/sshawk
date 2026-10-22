"""Drivers against captured command outputs, without SSH."""

from __future__ import annotations

from conftest import FakeConnection, assert_matches_expected
from sshawk.drivers import driver_for
from sshawk.drivers.base import prompt_hostname
from sshawk.drivers.cisco import parse_show_version
from sshawk.models import DeviceInfo, Status


def test_driver_collects_expected_inventory(spec):
    conn = FakeConnection(spec)
    info = DeviceInfo(host="192.0.2.1", status=Status.OK)
    raw: dict[str, str] = {}
    driver_for(spec.platform)(conn, info, raw).collect(neighbors=True)

    assert_matches_expected(info, spec.expected)
    assert set(raw) == set(conn.sent)  # every command output is kept for --save-raw


def test_detection_patterns_select_the_right_driver(spec):
    from sshawk.drivers import DRIVERS

    matches = []
    for driver in DRIVERS:
        for command, patterns in driver.detect.items():
            output = spec.commands.get(command, "")
            import re

            if any(re.search(p, output, re.MULTILINE | re.IGNORECASE) for p in patterns):
                matches.append(driver.device_type)
    assert matches[:1] == [driver_for(spec.platform).device_type]


def test_prompt_hostname_variants():
    assert prompt_hostname("<HW-01>") == "HW-01"
    assert prompt_hostname("[HW-01]") == "HW-01"
    assert prompt_hostname("VSP-01:1") == "VSP-01"
    assert prompt_hostname("* X440.12") == "X440"
    assert prompt_hostname("sw01") == "sw01"


def test_cisco_router_without_stack_table():
    text = (
        "Cisco IOS XE Software, Version 17.06.05\n"
        "Cisco IOS Software [Bengaluru], ISR Software (X86_64_LINUX_IOSD-UNIVERSALK9-M), "
        "Version 17.6.5, RELEASE SOFTWARE (fc2)\n"
        "RTR-01 uptime is 5 weeks, 1 day, 3 hours, 2 minutes\n"
        "cisco ISR4331/K9 (1RU) processor with 1795999K/6147K bytes of memory.\n"
        "Processor board ID FLM2222W0AB\n"
    )
    data = parse_show_version(text)
    assert data["os"] == "IOS-XE"
    assert data["version"] == "17.06.05"
    assert data["model"] == "ISR4331/K9"
    assert data["serial"] == "FLM2222W0AB"
    assert data["members"] == []
