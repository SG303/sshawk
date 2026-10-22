"""Credential sets and the ways to load them (file, environment, prompt)."""

from __future__ import annotations

import getpass
import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Credential:
    """One username/password pair, optionally with a Cisco enable secret.

    Credentials are tried in the order given; the first one that logs in wins.
    """

    username: str
    password: str = field(repr=False)
    secret: str = field(default="", repr=False)
    name: str = ""

    @property
    def label(self) -> str:
        return self.name or self.username


class CredentialError(ValueError):
    pass


def load_credentials_file(path: str | Path) -> list[Credential]:
    """Load credential sets from a TOML file.

    Example::

        [[credentials]]
        name = "tacacs"
        username = "netadmin"
        password_env = "SSHAWK_TACACS_PW"   # read from the environment ...

        [[credentials]]
        name = "local"
        username = "admin"
        password = "s3cret"                  # ... or stored inline
        secret = "en4ble"                    # optional Cisco enable secret

    Entries without any password source are prompted for interactively.
    """
    path = Path(path)
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise CredentialError(f"cannot read credentials file {path}: {exc}") from exc

    entries = data.get("credentials")
    if not isinstance(entries, list) or not entries:
        raise CredentialError(f"{path}: expected at least one [[credentials]] table")

    result = []
    for index, entry in enumerate(entries, start=1):
        username = entry.get("username")
        if not username:
            raise CredentialError(f"{path}: credentials entry {index} has no username")
        name = entry.get("name", "")
        label = name or username
        password = _resolve(entry, "password", label)
        if password is None:
            password = getpass.getpass(f"Password for {label}: ")
        secret = _resolve(entry, "secret", label) or ""
        result.append(Credential(username, password, secret, name))
    return result


def _resolve(entry: dict, key: str, label: str) -> str | None:
    if key in entry:
        return str(entry[key])
    env_key = f"{key}_env"
    if env_key in entry:
        value = os.environ.get(entry[env_key])
        if value is None:
            raise CredentialError(f"{label}: environment variable {entry[env_key]} is not set")
        return value
    return None


def credentials_from_env() -> Credential | None:
    """Build a credential from SSHAWK_USERNAME / SSHAWK_PASSWORD / SSHAWK_SECRET, if set."""
    username = os.environ.get("SSHAWK_USERNAME")
    password = os.environ.get("SSHAWK_PASSWORD")
    if not username or password is None:
        return None
    return Credential(username, password, os.environ.get("SSHAWK_SECRET", ""), name="env")


def prompt_credentials(usernames: list[str], ask_secret: bool = False) -> list[Credential]:
    """Prompt for the password (and optionally enable secret) of each username."""
    result = []
    for username in usernames:
        password = getpass.getpass(f"Password for {username}: ")
        secret = ""
        if ask_secret:
            secret = getpass.getpass(f"Enable secret for {username} (empty for none): ")
        result.append(Credential(username, password, secret))
    return result
