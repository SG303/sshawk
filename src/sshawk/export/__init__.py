"""Write scan results as JSON, CSV, Excel or HTML."""

from __future__ import annotations

import csv
import json
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sshawk import __version__
from sshawk.models import DeviceInfo

FORMATS = ("json", "csv", "xlsx", "html")

# (column title, value getter) per table; shared by CSV, Excel and HTML.
Column = tuple[str, Callable[..., Any]]

DEVICE_COLUMNS: list[Column] = [
    ("Host", lambda d: d.host),
    ("Status", lambda d: str(d.status)),
    ("Hostname", lambda d: d.hostname),
    ("Vendor", lambda d: d.vendor),
    ("OS", lambda d: d.os),
    ("Model", lambda d: d.model),
    ("Version", lambda d: d.version),
    ("Serial", lambda d: ", ".join(d.serials)),
    ("Members", lambda d: len(d.members) or ""),
    ("Uptime", lambda d: d.uptime),
    ("MAC", lambda d: d.mac),
    ("Credential", lambda d: d.credential),
    ("Device type", lambda d: d.device_type),
    ("Discovered via", lambda d: d.discovered_via),
    ("Error", lambda d: d.error),
    ("Warnings", lambda d: "; ".join(d.warnings)),
    ("Collected at", lambda d: d.collected_at),
]

MEMBER_COLUMNS: list[Column] = [
    ("Host", lambda d, m: d.host),
    ("Hostname", lambda d, m: d.hostname),
    ("Vendor", lambda d, m: d.vendor),
    ("Slot", lambda d, m: m.slot),
    ("Role", lambda d, m: m.role),
    ("Model", lambda d, m: m.model),
    ("Serial", lambda d, m: m.serial),
    ("Version", lambda d, m: m.version),
    ("MAC", lambda d, m: m.mac),
]

NEIGHBOR_COLUMNS: list[Column] = [
    ("Host", lambda d, n: d.host),
    ("Hostname", lambda d, n: d.hostname),
    ("Protocol", lambda d, n: n.protocol.upper()),
    ("Local interface", lambda d, n: n.local_interface),
    ("Neighbor", lambda d, n: n.remote_hostname),
    ("Neighbor interface", lambda d, n: n.remote_interface),
    ("Neighbor IP", lambda d, n: n.remote_ip),
    ("Neighbor platform", lambda d, n: n.remote_platform),
    ("Neighbor description", lambda d, n: n.remote_description),
]


def device_rows(devices: Sequence[DeviceInfo]) -> list[list[Any]]:
    return [[get(d) for _, get in DEVICE_COLUMNS] for d in devices]


def member_rows(devices: Sequence[DeviceInfo]) -> list[list[Any]]:
    return [[get(d, m) for _, get in MEMBER_COLUMNS] for d in devices for m in d.members]


def neighbor_rows(devices: Sequence[DeviceInfo]) -> list[list[Any]]:
    return [[get(d, n) for _, get in NEIGHBOR_COLUMNS] for d in devices for n in d.neighbors]


def titles(columns: list[Column]) -> list[str]:
    return [title for title, _ in columns]


def guess_format(path: str | Path) -> str:
    suffix = Path(path).suffix.lower().lstrip(".")
    fmt = {"xls": "xlsx", "htm": "html"}.get(suffix, suffix)
    if fmt not in FORMATS:
        raise ValueError(
            f"cannot tell output format from {path!r}; use one of {', '.join(FORMATS)}"
        )
    return fmt


def export(
    devices: Sequence[DeviceInfo],
    path: str | Path,
    fmt: str | None = None,
    csv_delimiter: str = ",",
    title: str = "",
) -> list[Path]:
    """Write devices to ``path`` and return the files written.

    CSV writes ``<name>.csv`` plus ``<name>_members.csv`` / ``<name>_neighbors.csv`` when
    there is stack-member or neighbor data.
    """
    path = Path(path)
    fmt = fmt or guess_format(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "json":
        path.write_text(to_json(devices), encoding="utf-8")
        return [path]
    if fmt == "csv":
        return write_csv(devices, path, csv_delimiter)
    if fmt == "xlsx":
        from sshawk.export.xlsx import write_xlsx

        write_xlsx(devices, path)
        return [path]
    if fmt == "html":
        from sshawk.export.html import render_html

        path.write_text(render_html(devices, title=title), encoding="utf-8")
        return [path]
    raise ValueError(f"unknown format {fmt!r}")


def to_json(devices: Sequence[DeviceInfo]) -> str:
    document = {
        "generator": f"sshawk {__version__}",
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "devices": [d.to_dict() for d in devices],
    }
    return json.dumps(document, indent=2, ensure_ascii=False, default=str) + "\n"


def load_json(path: str | Path) -> list[DeviceInfo]:
    """Read a JSON export back, e.g. to convert it to another format."""
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    items = document["devices"] if isinstance(document, dict) else document
    return [DeviceInfo.from_dict(item) for item in items]


def write_csv(devices: Sequence[DeviceInfo], path: Path, delimiter: str = ",") -> list[Path]:
    written = []
    tables = [
        (path, DEVICE_COLUMNS, device_rows(devices)),
        (path.with_name(f"{path.stem}_members.csv"), MEMBER_COLUMNS, member_rows(devices)),
        (path.with_name(f"{path.stem}_neighbors.csv"), NEIGHBOR_COLUMNS, neighbor_rows(devices)),
    ]
    for index, (target, columns, rows) in enumerate(tables):
        if index and not rows:
            continue
        # utf-8-sig: Excel only detects UTF-8 (umlauts in hostnames, ...) with a BOM.
        with target.open("w", newline="", encoding="utf-8-sig") as handle:
            writer = csv.writer(handle, delimiter=delimiter)
            writer.writerow(titles(columns))
            writer.writerows(rows)
        written.append(target)
    return written
