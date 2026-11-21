#!/usr/bin/env bash
# Start the Auditless dashboard on loopback with a pidfile.
# Override with AUDITLESS_HOST / AUDITLESS_PORT (default 127.0.0.1:8080).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOST="${AUDITLESS_HOST:-127.0.0.1}"
PORT="${AUDITLESS_PORT:-8080}"
PIDFILE="$ROOT/data/serve.pid"
LOG="$ROOT/data/serve.log"

mkdir -p "$ROOT/data"
cd "$ROOT"

if [[ -f "$PIDFILE" ]] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
  echo "already running (pid $(cat "$PIDFILE")) on $HOST:$PORT"
  exit 0
fi

setsid nohup .venv/bin/python -m auditless --serve \
  --serve-host "$HOST" --serve-port "$PORT" >>"$LOG" 2>&1 </dev/null &
echo $! >"$PIDFILE"
sleep 2

curl -fsS "http://$HOST:$PORT/healthz"
echo
echo "dashboard: http://$HOST:$PORT/  (pid $(cat "$PIDFILE"), log $LOG)"
