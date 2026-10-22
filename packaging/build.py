"""Build the portable single-file executable: ``uv run --group build python packaging/build.py``.

The result (dist/sshawk or dist/sshawk.exe) needs no Python on the target machine.
PyInstaller cannot cross-compile: build on Windows for Windows, on Linux for Linux.
For Linux, build on an old distribution (see .github/workflows/build.yml) so the binary
runs on older glibc versions too.
"""

from __future__ import annotations

import platform
import sys
from pathlib import Path

import PyInstaller.__main__

ROOT = Path(__file__).resolve().parent.parent


def main() -> None:
    args = [
        str(ROOT / "packaging" / "entry.py"),
        "--name", "sshawk",
        "--onefile",
        "--console",
        "--noconfirm",
        "--clean",
        "--distpath", str(ROOT / "dist"),
        "--workpath", str(ROOT / "build"),
        "--specpath", str(ROOT / "build"),
        # TextFSM templates are data files loaded at runtime.
        "--collect-data", "ntc_templates",
        "--collect-data", "sshawk",
        # rich loads its unicode width tables dynamically.
        "--collect-submodules", "rich._unicode_data",
        # Not needed at runtime; keeps the binary smaller.
        "--exclude-module", "tkinter",
        "--exclude-module", "pytest",
    ]
    if platform.system() == "Windows":
        args += ["--version-file", str(ROOT / "build" / "version_info.txt")]
        _write_windows_version_info()
    PyInstaller.__main__.run(args + sys.argv[1:])


def _write_windows_version_info() -> None:
    from sshawk import __version__

    parts = [int(p) for p in __version__.split(".")[:3]] + [0]
    numbers = ", ".join(str(p) for p in (parts + [0, 0, 0])[:4])
    (ROOT / "build").mkdir(exist_ok=True)
    (ROOT / "build" / "version_info.txt").write_text(
        f"""VSVersionInfo(
  ffi=FixedFileInfo(filevers=({numbers}), prodvers=({numbers})),
  kids=[
    StringFileInfo([StringTable('040904B0', [
      StringStruct('FileDescription', 'sshawk network inventory collector'),
      StringStruct('ProductName', 'sshawk'),
      StringStruct('FileVersion', '{__version__}'),
      StringStruct('ProductVersion', '{__version__}'),
      StringStruct('OriginalFilename', 'sshawk.exe'),
    ])]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])]),
  ],
)
""",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
