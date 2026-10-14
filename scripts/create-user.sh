#!/usr/bin/env bash
# create-user.sh — add (or update) a dashboard login.
#
# The server auto-creates one "admin" account on its very first run (random
# password printed once to its own log). Use this script to add named
# accounts for other people instead of sharing that one admin password.
#
# Requires: python3 with bcrypt (pip install bcrypt --break-system-packages
# if missing) and psql on PATH, pointed at the same Postgres the server uses.
#
# Usage:
#   ./create-user.sh --postgres "postgres://eg:eg@localhost:5432/endpointguard" \
#       --username jdoe --role TIER_1
#   (prompts for a password; or pass --password to script it non-interactively)
set -euo pipefail

POSTGRES_DSN="postgres://eg:eg@localhost:5432/endpointguard"
USERNAME=""
PASSWORD=""
ROLE="TIER_1"   # TIER_1 / TIER_2 / TIER_3 / ADMIN — purely a label today;
                # the REST API does not yet gate endpoints by role.

while [[ $# -gt 0 ]]; do
  case "$1" in
    --postgres) POSTGRES_DSN="$2"; shift 2 ;;
    --username) USERNAME="$2"; shift 2 ;;
    --password) PASSWORD="$2"; shift 2 ;;
    --role) ROLE="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
done

if [[ -z "$USERNAME" ]]; then
  echo "usage: $0 --username <name> [--role TIER_1|TIER_2|TIER_3|ADMIN] [--password <pw>] [--postgres <dsn>]" >&2
  exit 1
fi

if [[ -z "$PASSWORD" ]]; then
  read -r -s -p "Password for $USERNAME: " PASSWORD
  echo
  read -r -s -p "Confirm password: " PASSWORD_CONFIRM
  echo
  if [[ "$PASSWORD" != "$PASSWORD_CONFIRM" ]]; then
    echo "Passwords did not match." >&2
    exit 1
  fi
fi

HASH=$(python3 -c "
import bcrypt, sys
print(bcrypt.hashpw(sys.argv[1].encode(), bcrypt.gensalt()).decode())
" "$PASSWORD")

psql "$POSTGRES_DSN" -v ON_ERROR_STOP=1 \
  -c "INSERT INTO enterprise_control.users (username, password_hash, role)
      VALUES ('$USERNAME', '$HASH', '$ROLE')
      ON CONFLICT (username) DO UPDATE SET password_hash = EXCLUDED.password_hash, role = EXCLUDED.role;"

echo "User '$USERNAME' ($ROLE) created/updated."
