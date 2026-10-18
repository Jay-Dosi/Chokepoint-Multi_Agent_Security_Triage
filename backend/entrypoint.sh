#!/bin/sh
# Container entrypoint. On a platform that only gives one process per
# container (e.g. a free-tier Render web service), set MCP_MODE=embedded and
# this starts the MCP server as a background process on loopback before
# starting the API in the foreground. Local docker-compose never sets
# MCP_MODE, so it keeps using the separate `mcp` container unchanged.
set -e

if [ "${MCP_MODE:-external}" = "embedded" ]; then
    echo "entrypoint: starting MCP server in-process on 127.0.0.1:${MCP_PORT:-8765}"
    python -m mcp_server.server \
        --transport streamable-http \
        --host 127.0.0.1 \
        --port "${MCP_PORT:-8765}" &
fi

# Render (and most PaaS hosts) inject PORT at runtime and expect the app to
# bind to it; local docker-compose never sets it, so 8000 stays the default.
PORT="${PORT:-8000}"
echo "entrypoint: starting API on 0.0.0.0:${PORT}"
exec uvicorn app.main:app --host 0.0.0.0 --port "${PORT}" --log-level info
