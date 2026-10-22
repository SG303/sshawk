from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from fakedevice import PROFILES, DeviceSpec, all_specs  # noqa: E402
from sshawk.models import DeviceInfo  # noqa: E402

SPECS = all_specs()


class FakeConnection:
    """Stands in for a netmiko connection: serves fixture outputs, errors otherwise."""

    def __init__(self, spec: DeviceSpec):
        self.spec = spec
        self.base_prompt = spec.hostname
        self.sent: list[str] = []

    def send_command(self, command_string: str, **kwargs: object) -> str:
        self.sent.append(command_string)
        output = self.spec.commands.get(command_string)
        if output is None:
            return PROFILES[self.spec.platform].error.format(cmd=command_string)
        return output.rstrip("\n")


def assert_matches_expected(info: DeviceInfo, expected: dict) -> None:
    for key, value in expected.items():
        if key == "members":
            got = [
                {k: getattr(m, k) for k in item}
                for m, item in zip(info.members, value, strict=False)
            ]
            assert len(info.members) == len(value), info.members
            assert got == value
        elif key == "neighbors":
            assert len(info.neighbors) == value, info.neighbors
        else:
            assert getattr(info, key) == value, f"{key}: {getattr(info, key)!r} != {value!r}"


@pytest.fixture(params=SPECS, ids=[s.name for s in SPECS])
def spec(request: pytest.FixtureRequest) -> DeviceSpec:
    return request.param
