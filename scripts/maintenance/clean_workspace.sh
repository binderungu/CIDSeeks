#!/bin/zsh
set -euo pipefail

# Workspace default = repo root (relative to this script). Can override via:
#   WS=/path/to/repo ./scripts/maintenance/clean_workspace.sh
#   ./scripts/maintenance/clean_workspace.sh /path/to/repo
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEFAULT_WS="$(cd "$SCRIPT_DIR/../.." && pwd)"
: "${WS:=${1:-$DEFAULT_WS}}"

if [ ! -d "$WS" ]; then
  echo "Workspace not found: $WS" >&2
  exit 1
fi

# Safety guard to avoid accidental cleanup outside this project.
if [ ! -f "$WS/pyproject.toml" ] || [ ! -f "$WS/runner.py" ]; then
  echo "Refusing to run: '$WS' does not look like this repository." >&2
  exit 1
fi

echo "Cleaning workspace: $WS"

# 1) Coverage and common caches
rm -f "$WS/.coverage"
rm -rf "$WS/.pytest_cache" "$WS/.mypy_cache" "$WS/.ruff_cache" "$WS/.cursor"

# 2) Python build/runtime artifacts
find "$WS" -type d -name "__pycache__" -prune -exec rm -rf {} +
find "$WS" -type d -name "*.egg-info" -prune -exec rm -rf {} +
rm -rf "$WS/build" "$WS/dist"

# 3) macOS junk files
find "$WS" -type f -name ".DS_Store" -exec rm -f {} +

# 4) Logs cleanup (preserve docs)
if [ -d "$WS/logs" ]; then
  find "$WS/logs" -mindepth 1 ! -name "README.md" -exec rm -rf {} +
fi

# 5) SQLite runtime artifacts outside source-controlled DB
find "$WS" -maxdepth 1 -type f \( -name "*.db" -o -name "*.db-shm" -o -name "*.db-wal" \) -exec rm -f {} +

echo "Cleanup complete."

