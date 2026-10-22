import json

from fakedevice import DeviceSpec, FakeDevice
from sshawk.cli import main


def test_cli_scan_writes_outputs(tmp_path, monkeypatch):
    device = FakeDevice(DeviceSpec.load("voss_vsp4450")).start()
    monkeypatch.setenv("SSHAWK_USERNAME", "admin")
    monkeypatch.setenv("SSHAWK_PASSWORD", "admin")
    try:
        code = main(
            [
                "scan",
                device.target,
                "-q",
                "-o",
                str(tmp_path / "a.json"),
                "-o",
                str(tmp_path / "a.html"),
            ]
        )
    finally:
        device.stop()
    assert code == 0
    data = json.loads((tmp_path / "a.json").read_text(encoding="utf-8"))
    assert data["devices"][0]["hostname"] == "VSP-CORE-01"
    assert (tmp_path / "a.html").exists()

    assert main(["export", str(tmp_path / "a.json"), str(tmp_path / "b.xlsx")]) == 0
    assert (tmp_path / "b.xlsx").exists()


def test_cli_credentials_file(tmp_path, monkeypatch):
    device = FakeDevice(DeviceSpec.load("aoss_2930f")).start()
    creds = tmp_path / "creds.toml"
    creds.write_text(
        '[[credentials]]\nname = "old"\nusername = "admin"\npassword = "nope"\n\n'
        '[[credentials]]\nname = "new"\nusername = "admin"\npassword_env = "PW"\n'
    )
    monkeypatch.setenv("PW", "admin")
    out = tmp_path / "r.json"
    try:
        assert main(["scan", device.target, "-c", str(creds), "-q", "-o", str(out)]) == 0
    finally:
        device.stop()
    assert json.loads(out.read_text(encoding="utf-8"))["devices"][0]["credential"] == "new"


def test_cli_rejects_bad_input(capsys):
    assert main(["scan", "10.0.0.0/8", "-q"]) == 2
    assert main(["scan", "10.0.0.1", "-o", "out.txt"]) == 2
