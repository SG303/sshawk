"""Command line interface: ``sshawk scan``, ``sshawk export``, ``sshawk platforms``."""

from __future__ import annotations

import argparse
import ipaddress
import logging
import sys
from collections import Counter
from collections.abc import Sequence
from pathlib import Path

from rich.console import Console
from rich.logging import RichHandler
from rich.progress import BarColumn, MofNCompleteColumn, Progress, TextColumn, TimeElapsedColumn
from rich.table import Column, Table

from sshawk import __version__
from sshawk.credentials import (
    Credential,
    CredentialError,
    credentials_from_env,
    load_credentials_file,
    prompt_credentials,
)
from sshawk.drivers import DRIVERS
from sshawk.export import FORMATS, export, guess_format, load_json
from sshawk.models import DeviceInfo, Status
from sshawk.scanner import ScanOptions, parse_networks, scan
from sshawk.targets import TargetError, parse_targets, read_targets_file

console = Console(stderr=True)

EPILOG = """\
examples:
  sshawk scan 10.0.0.0/24 -u admin -o inventory.xlsx
  sshawk scan 10.0.0.1-50 10.0.1.10 -c creds.toml -o inv.xlsx -o inv.html
  sshawk scan 10.0.0.1 -u admin --crawl --scope 10.0.0.0/16 -o network.html
  sshawk export inventory.json inventory.csv --csv-delimiter ';'
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sshawk",
        description="Collect inventory data (model, serial, firmware, neighbors) from network "
        "devices over SSH.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"sshawk {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser(
        "scan",
        help="scan targets and collect inventory",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=EPILOG,
    )
    p.add_argument(
        "targets",
        nargs="*",
        metavar="TARGET",
        help="host, IP, CIDR (10.0.0.0/24) or range (10.0.0.1-50)",
    )
    p.add_argument(
        "-t",
        "--targets-file",
        action="append",
        default=[],
        type=Path,
        help="file with one target per line (# comments allowed)",
    )

    creds = p.add_argument_group("credentials (tried in order; first successful login wins)")
    creds.add_argument(
        "-u",
        "--user",
        action="append",
        default=[],
        dest="users",
        help="username; the password is prompted. Repeat for several accounts",
    )
    creds.add_argument(
        "-c", "--credentials", type=Path, help="TOML file with [[credentials]] entries (see README)"
    )
    creds.add_argument(
        "--enable", action="store_true", help="also prompt for a Cisco enable secret per -u user"
    )

    out = p.add_argument_group("output")
    out.add_argument(
        "-o",
        "--output",
        action="append",
        default=[],
        type=Path,
        help="output file; format from extension (.json .csv .xlsx .html). Repeatable",
    )
    out.add_argument(
        "-f", "--format", choices=FORMATS, help="force the output format (for a single -o)"
    )
    out.add_argument(
        "--csv-delimiter", default=",", help="CSV delimiter (use ';' for German Excel)"
    )
    out.add_argument("--title", default="", help="title for the HTML report (e.g. customer name)")
    out.add_argument(
        "--all",
        action="store_true",
        dest="include_unreachable",
        help="also list addresses without an SSH service in results",
    )
    out.add_argument(
        "--save-raw",
        type=Path,
        metavar="DIR",
        help="save raw command output per device (useful for bug reports)",
    )

    behaviour = p.add_argument_group("scan behaviour")
    behaviour.add_argument(
        "-w", "--workers", type=int, default=20, help="parallel connections (default 20)"
    )
    behaviour.add_argument(
        "-p",
        "--port",
        type=int,
        default=22,
        help="SSH port for targets without :port and for crawled neighbors",
    )
    behaviour.add_argument(
        "--timeout", type=float, default=10, help="connect/login timeout in seconds (default 10)"
    )
    behaviour.add_argument(
        "-d",
        "--device-type",
        metavar="TYPE",
        help="skip autodetection and use this platform (see 'sshawk platforms')",
    )
    behaviour.add_argument(
        "-n", "--neighbors", action="store_true", help="collect CDP/LLDP neighbors"
    )
    behaviour.add_argument(
        "--crawl",
        action="store_true",
        help="follow CDP/LLDP neighbors' management IPs (implies --neighbors)",
    )
    behaviour.add_argument(
        "--depth", type=int, default=3, help="max crawl hops from the given targets (default 3)"
    )
    behaviour.add_argument(
        "--scope",
        action="append",
        default=[],
        metavar="CIDR",
        help="only crawl into these networks (repeatable; default: anywhere)",
    )
    behaviour.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="CIDR",
        help="never connect to these networks/hosts (repeatable)",
    )
    _add_verbosity(p)

    e = sub.add_parser("export", help="convert a JSON result file to other formats")
    e.add_argument("input", type=Path, help="JSON file written by 'sshawk scan -o x.json'")
    e.add_argument("outputs", nargs="+", type=Path, help="output files (.csv .xlsx .html .json)")
    e.add_argument("--csv-delimiter", default=",")
    e.add_argument("--title", default="")
    _add_verbosity(e)

    sub.add_parser("platforms", help="list supported platforms")
    return parser


def _add_verbosity(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="more log output (-vv for debug incl. netmiko)",
    )
    parser.add_argument("-q", "--quiet", action="store_true", help="no progress or summary table")


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _setup_logging(getattr(args, "verbose", 0))
    try:
        if args.command == "platforms":
            return cmd_platforms()
        if args.command == "export":
            return cmd_export(args)
        return cmd_scan(args)
    except (TargetError, CredentialError, ValueError) as exc:
        console.print(f"[red]error:[/] {exc}")
        return 2
    except KeyboardInterrupt:
        console.print("[yellow]aborted[/]")
        return 130


def cmd_platforms() -> int:
    table = Table("Device type", "Vendor", "OS", "Detected by")
    for driver in DRIVERS:
        table.add_row(driver.device_type, driver.vendor, driver.os_name, ", ".join(driver.detect))
    Console().print(table)
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    devices = load_json(args.input)
    for output in args.outputs:
        for path in export(devices, output, csv_delimiter=args.csv_delimiter, title=args.title):
            console.print(f"wrote [bold]{path}[/]")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    specs = list(args.targets)
    for path in args.targets_file:
        specs += read_targets_file(path)
    if not specs:
        raise ValueError("no targets given (positional TARGET or -t FILE)")
    targets = parse_targets(specs, default_port=args.port)
    if args.format and len(args.output) != 1:
        raise ValueError("--format needs exactly one -o/--output")
    for output in args.output:
        if not args.format:
            guess_format(output)  # fail before scanning, not after

    credentials = _gather_credentials(args)
    options = ScanOptions(
        workers=args.workers,
        timeout=args.timeout,
        device_type=args.device_type,
        neighbors=args.neighbors,
        crawl=args.crawl,
        crawl_depth=args.depth,
        scope=parse_networks(args.scope),
        exclude=parse_networks(args.exclude),
        save_raw=args.save_raw,
        port=args.port,
    )

    with Progress(
        TextColumn("[bold]scanning"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        TextColumn("{task.fields[last]}"),
        console=console,
        disable=args.quiet,
        transient=True,
    ) as progress:
        task = progress.add_task("scan", total=len(targets), last="")
        done = 0

        def on_result(info: DeviceInfo) -> None:
            nonlocal done
            done += 1
            task_total = progress.tasks[0].total or 0
            if done > task_total:  # crawling added targets
                progress.update(task, total=done)
            progress.update(task, advance=1, last=f"{info.host} {info.status}")

        devices = scan(targets, credentials, options, progress=on_result)

    unreachable = [d for d in devices if d.status == Status.UNREACHABLE]
    shown = devices if args.include_unreachable else [d for d in devices if d not in unreachable]
    shown.sort(key=_sort_key)

    if not args.quiet:
        _print_summary(shown, len(unreachable), args.include_unreachable)
    for output in args.output:
        for path in export(
            shown, output, fmt=args.format, csv_delimiter=args.csv_delimiter, title=args.title
        ):
            console.print(f"wrote [bold]{path}[/]")
    if not args.output and not args.quiet:
        console.print("[dim]hint: use -o file.xlsx / .csv / .json / .html to save the results[/]")
    return 0 if any(d.ok for d in devices) else 1


def _gather_credentials(args: argparse.Namespace) -> list[Credential]:
    credentials: list[Credential] = []
    if args.credentials:
        credentials += load_credentials_file(args.credentials)
    if args.users:
        credentials += prompt_credentials(args.users, ask_secret=args.enable)
    if not credentials and (env := credentials_from_env()):
        credentials.append(env)
    if not credentials:
        if not sys.stdin.isatty():
            raise CredentialError("no credentials: use -u, -c or SSHAWK_USERNAME/SSHAWK_PASSWORD")
        username = console.input("Username: ").strip()
        if not username:
            raise CredentialError("no username given")
        credentials = prompt_credentials([username], ask_secret=args.enable)
    return credentials


def _sort_key(info: DeviceInfo) -> tuple:
    try:
        return (0, int(ipaddress.ip_address(info.host)), info.port)
    except ValueError:
        return (1, info.host, info.port)


_STATUS_STYLE = {
    Status.OK: "green",
    Status.PARTIAL: "yellow",
    Status.AUTH_FAILED: "red",
    Status.TIMEOUT: "red",
    Status.UNREACHABLE: "dim",
    Status.UNSUPPORTED: "magenta",
    Status.ERROR: "red",
}


def _print_summary(devices: list[DeviceInfo], unreachable: int, shown_unreachable: bool) -> None:
    table = Table(
        Column("Host", no_wrap=True),
        "Hostname",
        "Vendor",
        "Model",
        "Version",
        "Serial",
        "Status",
        title="sshawk results",
        title_justify="left",
    )
    for d in devices:
        status = f"[{_STATUS_STYLE[d.status]}]{d.status}[/]"
        if not d.ok and d.error:
            status += f" [dim]{d.error[:60]}[/]"
        serials = d.serials
        serial = (
            serials[0] + (f" (+{len(serials) - 1})" if len(serials) > 1 else "") if serials else ""
        )
        table.add_row(
            d.host if d.port == 22 else f"{d.host}:{d.port}",
            d.hostname,
            f"{d.vendor} {d.os}".strip(),
            d.model,
            d.version,
            serial,
            status,
        )
    out = Console()
    if devices:
        out.print(table)
    counts = Counter(str(d.status) for d in devices)
    parts = [f"{n} {status}" for status, n in counts.most_common()]
    if unreachable and not shown_unreachable:
        parts.append(f"{unreachable} without SSH (hidden, use --all)")
    console.print("summary: " + (", ".join(parts) or "nothing found"))


def _setup_logging(verbosity: int) -> None:
    level = logging.WARNING if verbosity == 0 else logging.INFO if verbosity == 1 else logging.DEBUG
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, show_path=False)],
    )
    if verbosity < 2:
        for noisy in ("netmiko", "paramiko"):
            logging.getLogger(noisy).setLevel(logging.CRITICAL)


if __name__ == "__main__":
    sys.exit(main())
