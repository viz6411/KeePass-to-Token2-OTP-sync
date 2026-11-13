"""Entrypoint for python -m t2_kpxc_sync."""

import sys
from .cli import main

if __name__ == "__main__":
    sys.exit(main())
