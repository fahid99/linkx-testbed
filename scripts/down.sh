#!/usr/bin/env bash
# Tear down the LinkX API + both MCP servers started by scripts/up.sh.
set -uo pipefail

stop() {
  local name="$1" pattern="$2"
  if pkill -f "$pattern" 2>/dev/null; then
    echo "stopped $name"
  else
    echo "not running: $name"
  fi
}

stop "LinkX API" "uvicorn app.main:app"
stop "Legit MCP" "mcp_servers.legitimate"
stop "Evil MCP"  "mcp_servers.malicious"
