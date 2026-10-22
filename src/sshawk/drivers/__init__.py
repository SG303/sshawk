"""Vendor drivers. Order matters: detection checks drivers in this order."""

from __future__ import annotations

from sshawk.drivers.aruba import ArubaAosCx, ArubaAosS
from sshawk.drivers.base import CommandError, Driver
from sshawk.drivers.cisco import CiscoIos
from sshawk.drivers.extreme import ExtremeExos, ExtremeVoss
from sshawk.drivers.huawei import HuaweiVrp

DRIVERS: list[type[Driver]] = [CiscoIos, ArubaAosCx, ArubaAosS, ExtremeExos, HuaweiVrp, ExtremeVoss]

# Alternative names users (or netmiko) may use for the same platform.
ALIASES = {
    "cisco_xe": "cisco_ios",
    "ios": "cisco_ios",
    "iosxe": "cisco_ios",
    "huawei_vrp": "huawei",
    "huawei_yunshan": "huawei",
    "vrp": "huawei",
    "exos": "extreme_exos",
    "voss": "extreme_vsp",
    "aoscx": "aruba_aoscx",
    "aos-cx": "aruba_aoscx",
    "aoss": "hp_procurve",
    "aos-s": "hp_procurve",
    "aruba_procurve": "hp_procurve",
    "aruba_osswitch": "hp_procurve",
    "procurve": "hp_procurve",
}


def driver_for(device_type: str) -> type[Driver]:
    name = ALIASES.get(device_type.lower(), device_type.lower())
    for driver in DRIVERS:
        if driver.device_type == name:
            return driver
    supported = ", ".join(d.device_type for d in DRIVERS)
    raise ValueError(f"unsupported device type {device_type!r} (supported: {supported})")


__all__ = ["ALIASES", "DRIVERS", "CommandError", "Driver", "driver_for"]
