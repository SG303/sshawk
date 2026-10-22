import pytest

from sshawk.targets import Target, TargetError, parse_targets, read_targets_file


def hosts(*specs):
    return [str(t) for t in parse_targets(specs)]


def test_single_and_hostname():
    assert hosts("10.0.0.1", "sw01.example.com") == ["10.0.0.1", "sw01.example.com"]


def test_cidr_skips_network_and_broadcast():
    assert hosts("10.0.0.0/30") == ["10.0.0.1", "10.0.0.2"]
    assert hosts("10.0.0.5/32") == ["10.0.0.5"]


def test_ranges():
    assert hosts("10.0.0.250-10.0.1.1") == [
        "10.0.0.250",
        "10.0.0.251",
        "10.0.0.252",
        "10.0.0.253",
        "10.0.0.254",
        "10.0.0.255",
        "10.0.1.0",
        "10.0.1.1",
    ]
    assert hosts("10.0.0.10-12") == ["10.0.0.10", "10.0.0.11", "10.0.0.12"]


def test_ports_and_dedup():
    assert parse_targets(["10.0.0.1:2222", "10.0.0.1", "10.0.0.1"]) == [
        Target("10.0.0.1", 2222),
        Target("10.0.0.1", 22),
    ]
    assert parse_targets(["10.0.0.1"], default_port=830) == [Target("10.0.0.1", 830)]


def test_ipv6():
    assert hosts("2001:db8::1") == ["2001:db8::1"]


@pytest.mark.parametrize(
    "spec", ["10.0.0.300", "10.0.0.5-10.0.0.1", "10.0.0.0/8", "bad_host!", "10.0.0.1:99999"]
)
def test_invalid(spec):
    with pytest.raises(TargetError):
        parse_targets([spec])


def test_targets_file(tmp_path):
    path = tmp_path / "targets.txt"
    path.write_text("# core\n10.0.0.1  # comment\n10.0.1.0/30, 10.0.2.5\n\n")
    assert read_targets_file(path) == ["10.0.0.1", "10.0.1.0/30", "10.0.2.5"]
