"""Entrypoint for python -m t2_kpxc_sync and PyInstaller executable."""

from __future__ import annotations

import sys
try:
    from .cli import main
except ImportError:
    from t2_kpxc_sync.cli import main

if __name__ == "__main__":
    try:
        sys.exit(main())
    except (KeyboardInterrupt, EOFError):
        sys.exit(0)
