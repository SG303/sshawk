# sshawk

Collect inventory data from network devices over SSH: hostname, model, serial numbers
(per stack member), firmware version, uptime and CDP/LLDP neighbors. Point it at IP
ranges, give it one or more credential sets, and get the result as Excel, CSV, JSON or
an HTML report. sshawk only runs read-only `show`/`display` commands.

Supported platforms (detected automatically):

| Vendor    | OS / platform            | netmiko device type |
|-----------|--------------------------|---------------------|
| Cisco     | IOS, IOS-XE              | `cisco_ios`         |
| Huawei    | VRP V200, YunShan V600   | `huawei`            |
| Extreme   | EXOS                     | `extreme_exos`      |
| Extreme   | VOSS / Fabric Engine     | `extreme_vsp`       |
| HPE Aruba | AOS-CX                   | `aruba_aoscx`       |
| HPE Aruba | AOS-S (ProCurve)         | `hp_procurve`       |

## Install

**Portable (no Python needed):** download `sshawk-windows-x86_64.exe` or
`sshawk-linux-x86_64` from the GitHub releases and copy it to the jump/management
server. The Linux binary runs on glibc 2.28 or newer (RHEL/Rocky/Alma 8+, Debian 10+,
Ubuntu 20.04+). Nothing else is needed, also no internet access.

**With Python 3.13+:** `uv tool install git+https://github.com/SG303/sshawk` (or
`pipx install ...`), or for development `uv sync` inside a clone.

## Command line

```
sshawk scan 10.0.0.0/24 -u admin -o inventory.xlsx
sshawk scan 10.0.0.1-50 10.0.1.10 sw-core.example.com -c creds.toml -o inv.xlsx -o inv.html
sshawk scan -t targets.txt -u netadmin -u admin --enable -o inv.csv --csv-delimiter ';'
sshawk scan 10.0.0.1 -u admin --crawl --scope 10.0.0.0/16 -o network.html --title "Customer AG"
sshawk export inventory.json inventory.xlsx      # convert a saved JSON result
sshawk platforms                                 # list supported platforms
```

Targets can be single hosts, hostnames, CIDR networks (`10.0.0.0/24`), ranges
(`10.0.0.10-10.0.0.50` or `10.0.0.10-50`) and `host:port`. A targets file has one entry
per line, `#` starts a comment.

Important options:

| Option | Meaning |
|---|---|
| `-u USER` | username, password is prompted. Repeat for several accounts |
| `-c FILE` | credentials file (see below) |
| `--enable` | also prompt for a Cisco enable secret |
| `-o FILE` | output; format from the extension `.xlsx .csv .json .html`. Repeatable |
| `-n` | also collect CDP/LLDP neighbors |
| `--crawl` | follow neighbors' management IPs (`--depth`, `--scope`, `--exclude`) |
| `-w N` | parallel sessions (default 20) |
| `-d TYPE` | skip autodetection, e.g. `-d huawei` |
| `--save-raw DIR` | keep the raw command output per device |
| `--all` | also list addresses where nothing answers on the SSH port |

Without `-u`/`-c`, sshawk uses `SSHAWK_USERNAME` / `SSHAWK_PASSWORD` /
`SSHAWK_SECRET` from the environment, or asks for a username.

### Credentials

Several credential sets are tried in the order given; the first successful login wins.
Once a set has worked, it is tried first on the following devices, which keeps failed
logins low. Still, every set before the right one is a failed login on that device; keep
that in mind with account lockout policies.

```toml
# creds.toml
[[credentials]]
name = "tacacs"
username = "netadmin"
password_env = "SSHAWK_TACACS_PW"   # read from an environment variable

[[credentials]]
name = "local"
username = "admin"
# no password key: prompted at start
secret = "enable-secret"            # optional, Cisco only
```

### Outputs

- **Excel**: sheets *Devices*, *Stack members* (one row per chassis with its serial),
  *Neighbors*. Failed devices are highlighted.
- **CSV**: `name.csv` plus `name_members.csv` / `name_neighbors.csv`. UTF-8 with BOM;
  use `--csv-delimiter ';'` for Excel with German/Swiss regional settings.
- **JSON**: everything, including extra fields per platform. Can be converted later
  with `sshawk export`.
- **HTML**: a single offline file with a firmware overview per platform (deviating
  releases stand out), the devices that could not be collected and why, and filterable,
  sortable tables. Prints cleanly.

## Python API

```python
import sshawk

creds = [sshawk.Credential("netadmin", "secret"), sshawk.Credential("admin", "fallback")]

# Scan and export
devices = sshawk.scan(["10.0.0.0/24", "10.0.1.1-20"], creds, workers=30, neighbors=True)
for device in devices:
    if device.ok:
        print(device.hostname, device.model, device.version, device.serials)
    else:
        print(device.host, device.status, device.error)
sshawk.export(devices, "inventory.xlsx")

# Work with one device
with sshawk.connect("10.0.0.1", creds) as session:
    print(session.device_type)                       # e.g. "huawei"
    print(session.send("display interface brief"))   # raw output
    rows = session.send("show interfaces status", parse=True)  # TextFSM (ntc-templates)
    info = session.collect(neighbors=True)           # same data as a scan
```

`scan()` never raises for single devices; check `device.status` (`ok`, `partial`,
`auth_failed`, `unreachable`, `timeout`, `unsupported`, `error`).

## How it works

1. TCP check on the SSH port (fast skip of empty addresses).
2. Login with the credential sets in order.
3. Platform detection on the same session: `show version`, `display version`,
   `show sys-info`; the session is then handed to the matching netmiko driver.
4. Per-platform commands:

| Platform | Commands |
|---|---|
| Cisco IOS/IOS-XE | `show version`, `show inventory`, `show cdp neighbors detail`, `show lldp neighbors detail` |
| Huawei | `display version`, `display esn` (fallback `display device manufacture-info`), `display stack`, `display lldp neighbor` |
| EXOS | `show switch`, `show version`, `show stacking`, `show slot`, `show lldp neighbors detailed` |
| VOSS | `show sys-info`, `show lldp neighbor` |
| AOS-CX | `show system`, `show version`, `show vsf`, `show lldp neighbor-info detail` |
| AOS-S | `show system`, `show modules`, `show stacking` / `show vsf`, `show lldp info remote-device detail`, `show cdp neighbors detail` |

If a device answers differently than expected, run with `--save-raw DIR` and use the
files to improve the parser and add a test fixture.

## Development

```
uv sync                       # dev environment
uv run pytest                 # unit + end-to-end tests
uv run ruff check src tests
```

The end-to-end tests run real SSH sessions against `tests/fakedevice.py`, a small SSH
server that emulates each vendor CLI (prompt, pager, error messages, enable mode) and
replies with the outputs in `tests/fixtures/devices/<name>/commands/`. Each fixture's
`device.toml` lists the values the parser must extract. To add a platform variant, drop
captured outputs into a new fixture directory.

Portable builds (PyInstaller cannot cross-compile):

```
uv run --group build python packaging/build.py   # native: dist/sshawk(.exe)
packaging/build-linux.sh                         # Linux binary for old glibc (docker)
```

GitHub Actions runs the tests on Linux and Windows and builds both binaries; pushing a
`v*` tag publishes them as a release.
