#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
BIN="$DIR/t2-kpxc-sync"

# 1. Check for standalone compiled binary
if [ -f "$BIN" ]; then
    if [ ! -x "$BIN" ]; then
        chmod +x "$BIN" 2>/dev/null || true
    fi
    if [ -x "$BIN" ]; then
        exec "$BIN" "$@"
    fi
fi

# 2. Fallback to Python environment
export PYTHONDONTWRITEBYTECODE=1

PYTHON_BIN=""
if [ -x "$DIR/.venv/bin/python" ]; then
    PYTHON_BIN="$DIR/.venv/bin/python"
elif [ -x "$DIR/venv/bin/python" ]; then
    PYTHON_BIN="$DIR/venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="python"
fi

if [ -z "$PYTHON_BIN" ]; then
    echo "[ERROR] Neither standalone executable 't2-kpxc-sync' nor python3 was found." >&2
    echo "Please download the standalone Linux release package or install Python 3.11+." >&2
    exit 1
fi

if [ -d "$DIR/src" ]; then
    export PYTHONPATH="$DIR/src${PYTHONPATH:+:$PYTHONPATH}"
fi

cd "$DIR"
exec "$PYTHON_BIN" -m t2_kpxc_sync "$@"
