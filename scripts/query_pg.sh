#!/usr/bin/env bash
sshpass -p kash ssh -o StrictHostKeyChecking=no kash@192.168.102.105 "docker exec eg-postgres psql -U eg -d endpointguard -c 'SELECT agent_id, hostname, status FROM enterprise_control.agents;'"
