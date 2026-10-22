"""sshawk - collect inventory data from network devices over SSH.

Quick start::

    import sshawk

    creds = [sshawk.Credential("admin", "secret")]
    devices = sshawk.scan(["10.0.0.0/24"], creds, workers=30)
    sshawk.export(devices, "inventory.xlsx")

    with sshawk.connect("10.0.0.1", creds) as session:
        print(session.send("show clock"))
"""

__version__ = "0.2.0"

from sshawk.credentials import Credential, credentials_from_env, load_credentials_file  # noqa: E402
from sshawk.export import export, load_json  # noqa: E402
from sshawk.models import DeviceInfo, Neighbor, StackMember, Status  # noqa: E402
from sshawk.scanner import ScanOptions, scan, scan_one  # noqa: E402
from sshawk.session import Session, SessionError, open_session  # noqa: E402

connect = open_session

__all__ = [
    "Credential",
    "DeviceInfo",
    "Neighbor",
    "ScanOptions",
    "Session",
    "SessionError",
    "StackMember",
    "Status",
    "__version__",
    "connect",
    "credentials_from_env",
    "export",
    "load_credentials_file",
    "load_json",
    "open_session",
    "scan",
    "scan_one",
]
