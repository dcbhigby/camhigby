#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Optional: override these in your shell before running this file.
export ADMIN_USERNAME="${ADMIN_USERNAME:-camhigby}"
export ADMIN_PASSWORD="${ADMIN_PASSWORD:-CamHigbyAdmin2026!}"
export HOST="${HOST:-127.0.0.1}"
export PORT="${PORT:-8000}"
export COOKIE_SECURE="${COOKIE_SECURE:-0}"

echo "Starting secure map server at http://${HOST}:${PORT}/"
echo "Admin username: ${ADMIN_USERNAME}"
echo "Open-page login remains on the website UI."
echo ""

open "http://${HOST}:${PORT}/" >/dev/null 2>&1 || true
python3 server.py
