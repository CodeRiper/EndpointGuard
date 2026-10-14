#!/usr/bin/env bash
# Quick end-to-end verification against a running dev stack.
# Usage: EG_API_TOKEN=dev-token-CHANGE-IN-PRODUCTION ./scripts/test-end-to-end.sh
set -euo pipefail

HOST="${EG_SERVER_HTTP:-http://localhost:8080}"
TOKEN="${EG_API_TOKEN:-dev-token-CHANGE-IN-PRODUCTION}"
AUTH="Authorization: Bearer $TOKEN"

echo "=== 1. Health check ==="
curl -sf "$HOST/api/health" | python3 -m json.tool

echo ""
echo "=== 2. List enrolled agents ==="
curl -sf -H "$AUTH" "$HOST/api/agents" | python3 -m json.tool

echo ""
echo "=== 3. Query recent events for first agent ==="
AGENT=$(curl -sf -H "$AUTH" "$HOST/api/agents" | python3 -c "
import sys,json; a=json.load(sys.stdin)
print(a[0]['agent_id'] if a else '')
")
if [ -n "$AGENT" ]; then
    echo "Agent: $AGENT"
    curl -sf -H "$AUTH" \
        "$HOST/api/events?agent_id=$AGENT&limit=5" | python3 -m json.tool
else
    echo "No agents enrolled yet — start the agent on a Windows machine"
fi

echo ""
echo "=== 4. ClickHouse: event-type distribution ==="
docker exec eg-clickhouse clickhouse-client \
    --query "SELECT event_type, count() as n FROM endpointguard.telemetry_events GROUP BY event_type ORDER BY n DESC"

echo ""
echo "=== 5. PostgreSQL: agent status ==="
docker exec eg-postgres psql -U eg -d endpointguard \
    -c "SELECT agent_id, hostname, status, last_heartbeat FROM enterprise_control.agents"

echo ""
echo "All checks passed."
