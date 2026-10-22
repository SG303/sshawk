"""End to end: real SSH sessions (netmiko/paramiko) against fake vendor CLIs."""

from __future__ import annotations

import socket

import pytest

import sshawk
from conftest import SPECS, assert_matches_expected
from fakedevice import DeviceSpec, FakeDevice
from sshawk import Credential, Status

# Loopback addresses referenced by the fixtures' CDP/LLDP management addresses.
ADDRESSES = {
    "cisco_c9300_stack": "127.0.0.11",
    "cisco_2960x": "127.0.0.12",
    "exos_x440_stack": "127.0.0.13",
    "huawei_s5735_yunshan": "127.0.0.14",
    "voss_vsp4450": "127.0.0.15",
    "aoscx_6300_vsf": "127.0.0.16",
    "aoss_2930f": "127.0.0.17",
    "huawei_s5720_stack": "127.0.0.18",
}

GOOD = Credential("admin", "admin", secret="en4ble", name="good")
WRONG = Credential("admin", "wrong", name="wrong")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def lab():
    port = _free_port()
    devices = {spec.name: FakeDevice(spec, ADDRESSES[spec.name], port).start() for spec in SPECS}
    yield port, devices
    for device in devices.values():
        device.stop()


def _by_host(results):
    return {r.host: r for r in results}


def test_scan_detects_and_collects_every_platform(lab):
    port, devices = lab
    targets = [d.target for d in devices.values()]
    results = sshawk.scan(targets, [GOOD], workers=len(targets), neighbors=True, timeout=10)

    by_host = _by_host(results)
    for name, device in devices.items():
        info = by_host[device.address]
        assert info.status == Status.OK, (name, info.error)
        assert info.device_type == sshawk.drivers.driver_for(device.spec.platform).device_type
        assert_matches_expected(info, device.spec.expected)


def test_enable_mode_is_entered_with_secret(lab):
    _, devices = lab
    device = devices["cisco_2960x"]
    with sshawk.connect(device.target, [GOOD]) as session:
        assert session.conn.check_enable_mode()
    assert "enable" in device.received


def test_credentials_are_tried_in_order_and_winner_is_reused(lab):
    _, devices = lab
    first, second = devices["exos_x440_stack"], devices["voss_vsp4450"]
    before = len(first.failed_logins) + len(second.failed_logins)
    results = sshawk.scan([first.target, second.target], [WRONG, GOOD], workers=1)

    assert [r.status for r in results] == [Status.OK, Status.OK]
    assert {r.credential for r in results} == {"good"}
    # Only the first device sees the wrong password; afterwards "good" is tried first.
    assert len(first.failed_logins) + len(second.failed_logins) - before == 1


def test_auth_failure_is_reported(lab):
    _, devices = lab
    info = sshawk.scan_one(devices["aoss_2930f"].target, [WRONG])
    assert info.status == Status.AUTH_FAILED
    assert "wrong" in info.error


def test_unreachable_port(lab):
    info = sshawk.scan_one(f"127.0.0.1:{_free_port()}", [GOOD])
    assert info.status == Status.UNREACHABLE


def test_explicit_device_type_skips_detection(lab):
    _, devices = lab
    device = devices["huawei_s5735_yunshan"]
    received = len(device.received)
    info = sshawk.scan_one(device.target, [GOOD], sshawk.ScanOptions(device_type="huawei"))
    assert info.status == Status.OK
    assert "show version" not in device.received[received:]


def test_crawl_follows_neighbors_within_scope(lab):
    port, devices = lab
    seed = devices["aoss_2930f"]
    results = sshawk.scan(
        [seed.address],
        [GOOD],
        crawl=True,
        crawl_depth=3,
        port=port,
        scope=sshawk.scanner.parse_networks(["127.0.0.0/8"]),
    )
    hosts = [r.host for r in results]
    # 2930F -> CX (LLDP) -> C9300 (LLDP) -> 2960X (CDP); the AP at 10.20.30.40 is out of scope.
    assert hosts == ["127.0.0.17", "127.0.0.16", "127.0.0.11", "127.0.0.12"]
    assert all(r.status == Status.OK for r in results)
    assert _by_host(results)["127.0.0.16"].discovered_via == "HP-2930F-01 (lldp)"


def test_crawl_depth_limit(lab):
    port, devices = lab
    results = sshawk.scan(
        [devices["aoss_2930f"].address],
        [GOOD],
        crawl=True,
        crawl_depth=1,
        port=port,
        scope=sshawk.scanner.parse_networks(["127.0.0.0/8"]),
    )
    assert [r.host for r in results] == ["127.0.0.17", "127.0.0.16"]


def test_save_raw_writes_outputs(lab, tmp_path):
    _, devices = lab
    sshawk.scan_one(devices["voss_vsp4450"].target, [GOOD], sshawk.ScanOptions(save_raw=tmp_path))
    files = list(tmp_path.glob("*.txt"))
    assert len(files) == 1
    assert "### show sys-info" in files[0].read_text(encoding="utf-8")


def test_session_send_parses_with_textfsm(lab):
    _, devices = lab
    with sshawk.connect(devices["cisco_c9300_stack"].target, [GOOD]) as session:
        rows = session.send("show inventory", parse=True)
    assert rows[0]["sn"] == "FOC2345X0AB"


@pytest.mark.parametrize("name", ["huawei_s5720_stack"])
def test_unknown_platform_is_unsupported(lab, name):
    spec = DeviceSpec(
        name="mystery",
        platform="cisco_ios",
        hostname="mystery",
        commands={"show version": "Totally Unknown OS 1.0"},
    )
    device = FakeDevice(spec).start()
    try:
        info = sshawk.scan_one(device.target, [GOOD])
    finally:
        device.stop()
    assert info.status == Status.UNSUPPORTED
