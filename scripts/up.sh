#!/usr/bin/env bash
# Bring up the LinkX API + both MCP servers, wait for health, seed the DB.
# Usage: source scripts/up.sh   (or ./scripts/up.sh, then run agents.run_trial in a new shell)
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

if [ -f .env ]; then
  set -a && . ./.env && set +a
fi

mkdir -p /tmp/linkx_logs

port_free() { ! lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1; }

port_free 8000 && nohup .venv/bin/python -m uvicorn app.main:app > /tmp/linkx_logs/api.log 2>&1 &
port_free 8001 && nohup .venv/bin/python -m mcp_servers.legitimate > /tmp/linkx_logs/mcp_legit.log 2>&1 &
port_free 8002 && nohup .venv/bin/python -m mcp_servers.malicious > /tmp/linkx_logs/mcp_evil.log 2>&1 &

# Accept any response (not just 200): the MCP /mcp endpoint replies 406 to a
# plain GET (it wants an SSE Accept header) — that still means the server is up.
check() {
  local name="$1" url="$2"
  for _ in $(seq 1 30); do
    code=$(curl -s -o /dev/null -w "%{http_code}" "$url" || true)
    if [ "$code" != "000" ]; then
      echo "OK  $name ($url) -> $code"
      return 0
    fi
    sleep 0.5
  done
  echo "FAIL $name ($url) did not come up — check its log in /tmp/linkx_logs/"
  return 1
}

check "LinkX API" http://localhost:8000/admin/health
check "Legit MCP" http://localhost:8001/mcp
check "Evil MCP"  http://localhost:8002/mcp

.venv/bin/python -m scripts.init_db

echo
echo "All three processes up, DB seeded. Run a trial, e.g.:"
echo "  .venv/bin/python -m agents.run_trial --model sonnet --attack tpa_p1 --topology chain --repeat 1 --trace"
echo
echo "Teardown: pkill -f uvicorn.app.main; pkill -f mcp_servers.legitimate; pkill -f mcp_servers.malicious"
