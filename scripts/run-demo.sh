#!/usr/bin/env bash
# End-to-end local demo — scan vulnerable-mcp with mcp-audit.
#
# Usage:  ./scripts/run-demo.sh
#
# Exit code: reflects the scanner's exit code. If the scanner finds issues
# (it should — we're scanning a deliberately vulnerable server), this script
# exits non-zero. That is correct behavior, not a bug.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if [[ ! -d .venv ]]; then
  echo "-> creating .venv"
  python3 -m venv .venv
fi

# shellcheck disable=SC1091
source .venv/bin/activate

echo "-> installing mcp-audit (editable) and dev deps"
pip install --quiet --upgrade pip
pip install --quiet -e ".[dev]"
pip install --quiet httpx

echo
echo "-> running tests"
pytest -q
echo

echo "-> listing registered checks"
python3 -m mcp_audit list-checks
echo

echo "-> scanning vulnerable-mcp (expect findings — non-zero exit is correct)"
echo
SCAN_EXIT=0
python3 -m mcp_audit scan --stdio "python3 -m vulnerable_mcp.server" || SCAN_EXIT=$?

echo
if [[ $SCAN_EXIT -ne 0 ]]; then
  echo "scanner exited $SCAN_EXIT (findings detected — expected for vulnerable-mcp)"
else
  echo "WARNING: scanner exited 0 against a vulnerable target — something is wrong"
fi

exit $SCAN_EXIT
