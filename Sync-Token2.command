#!/usr/bin/env bash
set -e
export PYTHONDONTWRITEBYTECODE=1
DIR="$(cd "$(dirname "$0")" && pwd)"
export PYTHONPATH="$DIR/src:$PYTHONPATH"
cd "$DIR"
python3 -m t2_kpxc_sync "$@"
