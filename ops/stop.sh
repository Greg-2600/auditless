#!/usr/bin/env bash
# Stop the dashboard started by ops/serve.sh.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PIDFILE="$ROOT/data/serve.pid"

if [[ ! -f "$PIDFILE" ]]; then
  echo "no pidfile at $PIDFILE"
  exit 0
fi

PID="$(cat "$PIDFILE")"
if kill -0 "$PID" 2>/dev/null; then
  kill "$PID"
  echo "stopped pid $PID"
else
  echo "pid $PID was not running"
fi
rm -f "$PIDFILE"
