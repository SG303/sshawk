"""Self-contained HTML report: works offline, prints cleanly, tables usable without JavaScript."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Sequence
from datetime import datetime
from html import escape

from sshawk import __version__
from sshawk.export import (
    MEMBER_COLUMNS,
    NEIGHBOR_COLUMNS,
    member_rows,
    neighbor_rows,
    titles,
)
from sshawk.models import DeviceInfo, Status

# Deviating firmware versions per OS family get these slots (validated all-pairs on the
# panel surface); the family's most common version stays neutral, the rest is hatched.
DEVIATION_SLOTS = 3

_FAILED_HINTS = {
    Status.AUTH_FAILED: "None of the credentials were accepted. Add the right account with -u or -c.",
    Status.TIMEOUT: "The device did not answer in time. Retry with a higher --timeout.",
    Status.UNSUPPORTED: "Logged in, but the platform is not supported yet. "
    "Send the --save-raw output to add it.",
    Status.ERROR: "The session failed. Run again with -vv for details.",
    Status.UNREACHABLE: "Nothing answers on the SSH port.",
}

_DEVICE_TABLE = [
    ("Host", "host", True),
    ("Hostname", "hostname", False),
    ("Vendor / OS", "platform", False),
    ("Model", "model", False),
    ("Version", "version", True),
    ("Serial", "serial", True),
    ("Members", "members", False),
    ("Uptime", "uptime", False),
    ("Status", "status", False),
]


def render_html(devices: Sequence[DeviceInfo], title: str = "") -> str:
    ok = [d for d in devices if d.ok]
    failed = [d for d in devices if not d.ok]
    generated = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M")
    heading = title or "Network inventory"

    body = [
        '<header class="masthead">',
        f"<h1>{escape(heading)}</h1>",
        f'<p class="lede">{_lede(ok, failed)}</p>',
        f'<p class="meta">Generated {generated} by sshawk {escape(__version__)}</p>',
        "</header>",
        _firmware_panel(ok),
        _failed_section(failed),
        _devices_section(devices),
        _table_section(
            "members",
            "Stack members and chassis",
            MEMBER_COLUMNS,
            member_rows(ok),
            mono={"Serial", "MAC", "Version"},
        ),
        _table_section(
            "neighbors",
            "CDP and LLDP neighbors",
            NEIGHBOR_COLUMNS,
            neighbor_rows(ok),
            mono={"Neighbor IP"},
        ),
    ]
    return _PAGE.format(title=escape(heading), css=_CSS, body="\n".join(body), js=_JS)


def _lede(ok: list[DeviceInfo], failed: list[DeviceInfo]) -> str:
    if not ok and not failed:
        return "No devices answered. Check the targets and that SSH is reachable from here."
    vendors = Counter(d.vendor for d in ok)
    members = sum(max(len(d.members), 1) for d in ok)
    parts = [f"<strong>{len(ok)}</strong> device{'s' if len(ok) != 1 else ''} collected"]
    if members != len(ok):
        parts[0] += f" ({members} chassis incl. stack members)"
    if vendors:
        parts.append(", ".join(f"{n} {escape(v)}" for v, n in vendors.most_common()))
    sentence = "; ".join(parts) + "."
    if failed:
        sentence += f' <a href="#failed">{len(failed)} could not be collected.</a>'
    return sentence


def _firmware_panel(devices: list[DeviceInfo]) -> str:
    if not devices:
        return ""
    families: dict[str, list[DeviceInfo]] = defaultdict(list)
    for device in devices:
        families[f"{device.vendor} {device.os}".strip() or "Unknown"].append(device)

    rows = []
    for family, members in sorted(families.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        counts = Counter(d.version or "unknown" for d in members)
        ranked = [v for v, _ in counts.most_common()]
        baseline = ranked[0]
        slots = {v: f"s{i}" for i, v in enumerate(ranked[1 : DEVIATION_SLOTS + 1], start=1)}

        def slot(version: str, slots: dict[str, str] = slots, baseline: str = baseline) -> str:
            return "base" if version == baseline else slots.get(version, "other")

        legend = []
        for version in ranked:
            css = slot(version)
            label = "other" if css == "other" else version
            if css == "other" and any("other" in item for item in legend):
                continue
            n = (
                counts[version]
                if css != "other"
                else sum(counts[v] for v in ranked if slot(v) == "other")
            )
            legend.append(
                f'<li><i class="chip {css}" aria-hidden="true"></i>'
                f"{escape(label)} <span>{n}</span></li>"
            )
        verdict = "All on one release" if len(ranked) == 1 else f"{len(ranked)} releases in use"

        model_rows = []
        by_model: dict[str, list[DeviceInfo]] = defaultdict(list)
        for device in members:
            by_model[device.model or "unknown model"].append(device)
        for model, group in sorted(by_model.items(), key=lambda kv: (-len(kv[1]), kv[0])):
            group.sort(key=lambda d: (ranked.index(d.version or "unknown"), d.hostname))
            ports = "".join(
                f'<a class="port {slot(d.version or "unknown")}" href="#dev-{_anchor(d)}" '
                f'data-tip="{escape(_tip(d))}" aria-label="{escape(_tip(d))}"></a>'
                for d in group
            )
            model_rows.append(
                f'<div class="model"><span class="model-name">{escape(model)}</span>'
                f'<span class="model-count">{len(group)}</span>'
                f'<div class="ports">{ports}</div></div>'
            )

        rows.append(
            f'<section class="family"><div class="family-head"><h3>{escape(family)}</h3>'
            f'<p>{verdict}</p><ul class="legend">{"".join(legend)}</ul></div>'
            f'<div class="faceplate">{"".join(model_rows)}</div></section>'
        )

    return (
        '<section class="firmware" aria-labelledby="fw-title">'
        '<h2 id="fw-title">Firmware by platform</h2>'
        '<p class="section-note">One port per device. Grey is the release most devices of that '
        "platform run; coloured ports deviate from it. Select a port to jump to the device.</p>"
        + "".join(rows)
        + "</section>"
    )


def _tip(device: DeviceInfo) -> str:
    return f"{device.hostname or device.host}, {device.host}, {device.version or 'unknown'}"


def _anchor(device: DeviceInfo) -> str:
    return f"{device.host}-{device.port}".replace(":", "-").replace(".", "-")


def _failed_section(failed: list[DeviceInfo]) -> str:
    if not failed:
        return ""
    groups: dict[Status, list[DeviceInfo]] = defaultdict(list)
    for device in failed:
        groups[device.status].append(device)
    blocks = []
    for status, items in groups.items():
        hosts = "".join(
            f"<li><code>{escape(d.host)}</code> <span>{escape(d.error)}</span></li>" for d in items
        )
        blocks.append(
            f'<div class="failure"><h3><span class="status-icon" aria-hidden="true">!</span>'
            f"{escape(_status_label(status))} ({len(items)})</h3>"
            f"<p>{escape(_FAILED_HINTS.get(status, ''))}</p><ul>{hosts}</ul></div>"
        )
    return (
        '<section id="failed" class="failed" aria-labelledby="failed-title">'
        f'<h2 id="failed-title">Not collected</h2>{"".join(blocks)}</section>'
    )


def _status_label(status: Status) -> str:
    return {
        Status.OK: "Collected",
        Status.PARTIAL: "Partly collected",
        Status.AUTH_FAILED: "Login failed",
        Status.UNREACHABLE: "No SSH service",
        Status.TIMEOUT: "Timed out",
        Status.UNSUPPORTED: "Unsupported platform",
        Status.ERROR: "Session error",
    }[status]


def _devices_section(devices: Sequence[DeviceInfo]) -> str:
    head = "".join(
        f'<th scope="col" data-key="{key}">{escape(title)}</th>' for title, key, _ in _DEVICE_TABLE
    )
    rows = []
    for d in devices:
        serials = d.serials
        values = {
            "host": d.host if d.port == 22 else f"{d.host}:{d.port}",
            "hostname": d.hostname,
            "platform": f"{d.vendor} {d.os}".strip(),
            "model": d.model,
            "version": d.version,
            "serial": "\n".join(serials),
            "members": str(len(d.members)) if len(d.members) > 1 else "",
            "uptime": d.uptime,
            "status": _status_label(d.status),
        }
        cells = []
        for _, key, mono in _DEVICE_TABLE:
            value = escape(values[key]).replace("\n", "<br>")
            css = ' class="mono"' if mono else ""
            if key == "status":
                css = f' class="st st-{d.status}"'
                if d.error:
                    value += f"<small>{escape(d.error)}</small>"
            cells.append(f"<td{css}>{value}</td>")
        rows.append(f'<tr id="dev-{_anchor(d)}">{"".join(cells)}</tr>')
    return (
        '<section id="devices" aria-labelledby="devices-title">'
        '<div class="table-head"><h2 id="devices-title">Devices</h2>'
        '<label class="filter">Filter <input type="search" data-filter="devices-table" '
        'placeholder="hostname, model, version, serial …"></label></div>'
        f'<div class="scroll"><table id="devices-table" class="data sortable"><thead><tr>{head}'
        f"</tr></thead><tbody>{''.join(rows)}</tbody></table></div></section>"
    )


def _table_section(anchor: str, heading: str, columns, rows, mono=frozenset()) -> str:
    if not rows:
        return ""
    header = titles(columns)
    head = "".join(f'<th scope="col">{escape(t)}</th>' for t in header)
    body = "".join(
        "<tr>"
        + "".join(
            f"<td{' class=mono' if header[i] in mono else ''}>{escape(str(v or ''))}</td>"
            for i, v in enumerate(row)
        )
        + "</tr>"
        for row in rows
    )
    return (
        f'<section id="{anchor}" aria-labelledby="{anchor}-title"><details>'
        f'<summary><h2 id="{anchor}-title">{escape(heading)}</h2> <span>{len(rows)} rows</span>'
        f'</summary><div class="table-head"><label class="filter">Filter <input type="search" '
        f'data-filter="{anchor}-table"></label></div><div class="scroll">'
        f'<table id="{anchor}-table" class="data sortable"><thead><tr>{head}</tr></thead>'
        f"<tbody>{body}</tbody></table></div></details></section>"
    )


_PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="generator" content="sshawk">
<title>{title}</title>
<style>{css}</style>
</head>
<body>
<main>
{body}
</main>
<div id="tip" role="tooltip" hidden></div>
<script>{js}</script>
</body>
</html>
"""

_CSS = """
:root {
  color-scheme: light;
  --paper: #ffffff;
  --ink: #000000;
  --ink-2: #545b63;
  --ink-3: #848b93;
  --rule: #dde1e5;
  --wash: #f2f4f6;
  --panel: #262c32;
  --panel-ink: #e9edf1;
  --panel-ink-2: #9aa3ac;
  --base: #b4bcc4;
  --s1: #3987e5;
  --s2: #d95926;
  --s3: #199e70;
  --critical: #c42f2f;
  --warning: #9a6700;
  --label: "Bahnschrift", "DIN Alternate", "DIN 2014", "Barlow Semi Condensed", "Arial Narrow", sans-serif;
  --text: "Segoe UI", system-ui, -apple-system, "Helvetica Neue", sans-serif;
  --mono: "Cascadia Mono", Consolas, "SF Mono", ui-monospace, monospace;
}
@media (prefers-color-scheme: dark) {
  :root {
    color-scheme: dark;
    --paper: #15191d;
    --ink: #f1f3f5;
    --ink-2: #b3bbc3;
    --ink-3: #8a939c;
    --rule: #2f363d;
    --wash: #1d2227;
    --critical: #ef6b6b;
    --warning: #e0a43a;
  }
}
* { box-sizing: border-box; }
html { background: var(--paper); color: var(--ink); }
body { margin: 0; font: 15px/1.5 var(--text); }
main { max-width: 1240px; margin: 0 auto; padding: 48px 32px 96px; }
h1, h2, h3, th, summary, .model-name, .legend { font-family: var(--label); }
h1 { font-size: 44px; line-height: 1.05; font-weight: 600; letter-spacing: -0.01em; margin: 0 0 16px; font-stretch: semi-condensed; }
h2 { font-size: 24px; font-weight: 600; margin: 0 0 8px; }
h3 { font-size: 17px; font-weight: 600; margin: 0; }
a { color: inherit; }
.masthead { border-bottom: 3px solid var(--ink); padding-bottom: 24px; margin-bottom: 40px; }
.lede { font-size: 19px; max-width: 70ch; margin: 0 0 8px; }
.lede a { color: var(--critical); }
.meta, .section-note { color: var(--ink-2); font-size: 13px; margin: 0; max-width: 75ch; }
section { margin-bottom: 48px; }
.section-note { margin-bottom: 20px; }

/* Firmware faceplates: the one loud element of the page. */
.family { margin-bottom: 20px; }
.family-head { display: flex; flex-wrap: wrap; align-items: baseline; gap: 4px 20px; margin-bottom: 8px; }
.family-head p { margin: 0; color: var(--ink-2); font-size: 14px; }
.legend { display: flex; flex-wrap: wrap; gap: 4px 16px; list-style: none; margin: 0 0 0 auto; padding: 0; font-size: 14px; }
.legend li { display: flex; align-items: center; gap: 6px; }
.legend span { color: var(--ink-2); font-variant-numeric: tabular-nums; }
.faceplate { background: var(--panel); color: var(--panel-ink); border-radius: 6px; padding: 6px 16px; }
.model { display: grid; grid-template-columns: minmax(140px, 220px) 32px 1fr; align-items: center; gap: 12px; padding: 8px 0; }
.model + .model { border-top: 1px solid #3a4148; }
.model-name { font-size: 15px; letter-spacing: 0.02em; overflow-wrap: anywhere; }
.model-count { color: var(--panel-ink-2); font-variant-numeric: tabular-nums; text-align: right; font-size: 14px; }
.ports { display: flex; flex-wrap: wrap; gap: 3px; }
.port, .chip { display: inline-block; width: 16px; height: 13px; border-radius: 2px 2px 4px 4px; background: var(--base); }
.chip { width: 14px; height: 11px; }
.port { position: relative; outline-offset: 2px; }
.port::after { content: ""; position: absolute; left: 4px; right: 4px; bottom: 2px; height: 3px; border-radius: 1px; background: rgba(0,0,0,.28); }
.port:hover, .port:focus-visible { outline: 2px solid var(--panel-ink); }
.s1 { background: var(--s1); } .s2 { background: var(--s2); } .s3 { background: var(--s3); }
.other { background: repeating-linear-gradient(45deg, var(--base) 0 2px, var(--panel) 2px 4px); }
.legend .chip.other { background: repeating-linear-gradient(45deg, var(--ink-3) 0 2px, transparent 2px 4px); }
.legend .chip.base { background: var(--base); outline: 1px solid var(--ink-3); outline-offset: -1px; }

/* Failures */
.failed { border-left: 4px solid var(--critical); padding-left: 20px; }
.failure { margin-top: 16px; }
.failure h3 { display: flex; align-items: center; gap: 8px; }
.failure p { margin: 4px 0 8px; color: var(--ink-2); max-width: 75ch; }
.failure ul { list-style: none; margin: 0; padding: 0; columns: 2 340px; column-gap: 32px; }
.failure li { break-inside: avoid; padding: 2px 0; font-size: 14px; }
.failure li span { color: var(--ink-2); }
.status-icon { display: inline-grid; place-items: center; width: 18px; height: 18px; border-radius: 50%; background: var(--critical); color: #fff; font: 700 12px/1 var(--text); }
code, .mono { font-family: var(--mono); font-size: 13px; }

/* Tables */
.table-head { display: flex; flex-wrap: wrap; align-items: baseline; justify-content: space-between; gap: 8px 24px; margin-bottom: 8px; }
.filter { font-size: 13px; color: var(--ink-2); display: flex; align-items: center; gap: 8px; }
.filter input { font: 14px var(--text); color: var(--ink); background: var(--paper); border: 1px solid var(--ink-3); border-radius: 4px; padding: 6px 10px; width: min(320px, 70vw); }
.filter input:focus-visible { outline: 2px solid var(--s1); outline-offset: 1px; }
.scroll { overflow-x: auto; }
table.data { border-collapse: collapse; width: 100%; font-size: 14px; }
.data th { text-align: left; font-weight: 600; font-size: 14px; letter-spacing: 0.02em; padding: 8px 12px 8px 0; border-bottom: 2px solid var(--ink); white-space: nowrap; vertical-align: bottom; }
.data td { padding: 7px 12px 7px 0; border-bottom: 1px solid var(--rule); vertical-align: top; }
.data tbody tr:hover { background: var(--wash); }
.data tr:target { background: var(--wash); box-shadow: inset 4px 0 0 var(--s1); }
.data th button { all: unset; cursor: pointer; }
.data th button:focus-visible { outline: 2px solid var(--s1); }
.data th[aria-sort="ascending"] button::after { content: " ▲"; font-size: 10px; }
.data th[aria-sort="descending"] button::after { content: " ▼"; font-size: 10px; }
.st { white-space: nowrap; }
.st small { display: block; white-space: normal; color: var(--ink-2); font-size: 12px; max-width: 40ch; }
.st-partial { color: var(--warning); }
.st-auth_failed, .st-timeout, .st-error, .st-unsupported { color: var(--critical); }
.st-unreachable { color: var(--ink-3); }
details summary { cursor: pointer; list-style: none; display: flex; align-items: baseline; gap: 12px; margin-bottom: 8px; }
details summary::-webkit-details-marker { display: none; }
details summary h2::before { content: "+ "; color: var(--ink-3); }
details[open] summary h2::before { content: "− "; }
details summary span { color: var(--ink-2); font-size: 14px; font-family: var(--text); }
#tip { position: fixed; z-index: 10; pointer-events: none; background: var(--ink); color: var(--paper); font-size: 13px; padding: 4px 8px; border-radius: 4px; white-space: nowrap; }
@media (max-width: 640px) {
  main { padding: 24px 16px 64px; }
  h1 { font-size: 32px; }
  .model { grid-template-columns: 1fr auto; }
  .ports { grid-column: 1 / -1; }
  .legend { margin-left: 0; }
}
@media print {
  :root { color-scheme: light; --paper: #fff; --ink: #000; --ink-2: #444; --rule: #ccc; }
  main { max-width: none; padding: 0; }
  .filter, #tip { display: none !important; }
  details > *:not(summary) { display: block !important; }
  details summary h2::before { content: ""; }
  .faceplate, .port, .chip { print-color-adjust: exact; -webkit-print-color-adjust: exact; }
  tr { break-inside: avoid; }
  .scroll { overflow: visible; }
}
@media (prefers-reduced-motion: reduce) { * { scroll-behavior: auto !important; } }
"""

_JS = """
(() => {
  const collator = new Intl.Collator(undefined, { numeric: true, sensitivity: 'base' });
  const ipKey = (s) => /^\\d+\\.\\d+\\.\\d+\\.\\d+/.test(s)
    ? s.split(/[.:]/).map((p) => p.padStart(5, '0')).join('.') : null;

  document.querySelectorAll('table.sortable').forEach((table) => {
    table.querySelectorAll('thead th').forEach((th, index) => {
      const button = document.createElement('button');
      button.type = 'button';
      button.textContent = th.textContent;
      th.textContent = '';
      th.appendChild(button);
      button.addEventListener('click', () => {
        const dir = th.getAttribute('aria-sort') === 'ascending' ? 'descending' : 'ascending';
        table.querySelectorAll('thead th').forEach((h) => h.removeAttribute('aria-sort'));
        th.setAttribute('aria-sort', dir);
        const body = table.tBodies[0];
        const rows = [...body.rows];
        const text = (row) => row.cells[index].innerText.trim();
        rows.sort((a, b) => {
          const x = text(a), y = text(b);
          const ix = ipKey(x), iy = ipKey(y);
          const result = ix && iy ? ix.localeCompare(iy) : collator.compare(x, y);
          return dir === 'ascending' ? result : -result;
        });
        rows.forEach((row) => body.appendChild(row));
      });
    });
  });

  document.querySelectorAll('input[data-filter]').forEach((input) => {
    const table = document.getElementById(input.dataset.filter);
    input.addEventListener('input', () => {
      const terms = input.value.toLowerCase().split(/\\s+/).filter(Boolean);
      [...table.tBodies[0].rows].forEach((row) => {
        const text = row.innerText.toLowerCase();
        row.hidden = !terms.every((t) => text.includes(t));
      });
    });
  });

  const tip = document.getElementById('tip');
  const show = (el) => {
    const r = el.getBoundingClientRect();
    tip.textContent = el.dataset.tip;
    tip.hidden = false;
    const left = Math.min(r.left, window.innerWidth - tip.offsetWidth - 8);
    tip.style.left = Math.max(8, left) + 'px';
    tip.style.top = (r.top - tip.offsetHeight - 6) + 'px';
  };
  document.querySelectorAll('.port').forEach((port) => {
    port.addEventListener('mouseenter', () => show(port));
    port.addEventListener('focus', () => show(port));
    port.addEventListener('mouseleave', () => { tip.hidden = true; });
    port.addEventListener('blur', () => { tip.hidden = true; });
  });
})();
"""
