"""PyInstaller entry point for the portable sshawk executable."""

import sys

from sshawk.cli import main

if __name__ == "__main__":
    sys.exit(main())
