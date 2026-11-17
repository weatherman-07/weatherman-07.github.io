#!/usr/bin/env bash
# Run the site from WSL / Linux / macOS.
#   ./dev.sh            build into ./dist
#   ./dev.sh --serve    build + serve on http://localhost:8000 and rebuild on save (shows drafts)
set -euo pipefail
cd "$(dirname "$0")"
VENV=".venv-wsl"   # separate from the Windows .venv so the two never clash
[ -d "$VENV" ] || python3 -m venv "$VENV"
"$VENV/bin/pip" install -q -r requirements-media.txt
exec "$VENV/bin/python" build.py "$@"
