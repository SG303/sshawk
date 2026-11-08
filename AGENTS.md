# sshawk

CLI and Python API that collects inventory data (models, serials, firmware,
stack members, CDP/LLDP neighbors) from network devices over SSH and exports
it to Excel and HTML. Used by me as a network engineer on jump hosts, often
without internet access. Public repo.

Follows the SG303 baseline v1 (`sgstack/global/AGENTS.md`,
`sgstack/baseline/tools.md`). If you cannot read those: work on a branch,
open a PR, merge only with green checks (squash); never commit secrets or
personal data; English for everything in the repo; talk to me in German.

## Commands

- Setup: `uv sync`
- Test: `uv run pytest` (unit and end-to-end tests)
- Lint and format: `uv run ruff check --fix && uv run ruff format`
- Run locally: `uv run sshawk --help`
- Portable builds: `uv run --group build python packaging/build.py` (native
  binary in `dist/`), `packaging/build-linux.sh` (Linux binary for old glibc,
  needs Docker)

## Release

1. In a PR: bump the version in `pyproject.toml` and `src/sshawk/__init__.py`
   (both must match), run `uv lock`, move `## [Unreleased]` in CHANGELOG.md to
   the new version with today's date.
2. After the merge, tag the merge commit on `main` with `v<version>` and push
   the tag. CI builds the Windows and Linux binaries and publishes the GitHub
   release with SHA256SUMS. Never move or reuse a tag.

## Conventions

- Layout: `src/sshawk/` with `scanner.py` (scan flow), `session.py` (SSH
  login and platform detection), `drivers/` (one module per vendor),
  `export/` (xlsx, html), `templates/` (own TextFSM templates).
- Platform detection runs on one session (`show version`, `display version`,
  `show sys-info`) and then hands it to the matching netmiko driver.
- End-to-end tests run real SSH sessions against `tests/fakedevice.py`, which
  replays outputs from `tests/fixtures/devices/<name>/commands/`; each
  fixture's `device.toml` lists the expected values. New platform variants:
  add a fixture directory with captured outputs (from `--save-raw DIR`).
- paramiko stays below 5: version 5 removed SHA-1 host keys and key exchanges
  that older switches need. Dependabot ignores paramiko majors.
- Credential files (`creds.toml`) and captured device outputs from real
  networks never go into the repo; fixtures must be anonymised.
- The binaries must run on Windows and on old Linux (glibc 2.28, tested on
  Debian 10); keep both builds green.

## Deviations from baseline

- none
