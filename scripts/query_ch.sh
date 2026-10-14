#!/usr/bin/env bash
sshpass -p kash ssh -o StrictHostKeyChecking=no kash@192.168.102.105 "docker exec eg-clickhouse clickhouse-client --query \"SELECT event_time, event_type, agent_id, raw_json FROM endpointguard.telemetry_events WHERE event_type LIKE '%AGENT%' ORDER BY event_time DESC LIMIT 6\""
