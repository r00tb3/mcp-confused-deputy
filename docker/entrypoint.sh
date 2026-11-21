#!/bin/sh
# Start three processes and supervise them: if any dies, take the container down
# rather than serving a half-broken lab.
set -eu

VULN_PORT="${VULN_PORT:-8765}"
CLEAN_PORT="${CLEAN_PORT:-8766}"
UI_PORT="${UI_PORT:-8080}"
GRANT_TOKEN="${GRANT_TOKEN:-lab-elevation-grant}"

echo "mcp-confused-deputy"
echo "  vuln   :${VULN_PORT}"
echo "  clean  :${CLEAN_PORT}"
echo "  ui     :${UI_PORT}"
echo

# Each broker gets its own workspace copy and state dir so the two modes never
# share a service generation. Without this, Act 4 compares a state it already
# mutated.
for mode in vuln clean; do
  rm -rf "/lab/run/${mode}/workspace" "/lab/run/${mode}/state"
  cp -R /lab/lab/workspace "/lab/run/${mode}/workspace"
  mkdir -p "/lab/run/${mode}/state"
done

python3 /lab/lab/broker.py \
  --mode vuln \
  --host 0.0.0.0 --port "${VULN_PORT}" \
  --workspace "/lab/run/vuln/workspace" \
  --state-dir "/lab/run/vuln/state" &
VULN_PID=$!

python3 /lab/lab/broker.py \
  --mode clean \
  --host 0.0.0.0 --port "${CLEAN_PORT}" \
  --workspace "/lab/run/clean/workspace" \
  --state-dir "/lab/run/clean/state" \
  --grant-token "${GRANT_TOKEN}" &
CLEAN_PID=$!

python3 -m http.server "${UI_PORT}" \
  --bind 0.0.0.0 \
  --directory /lab/web-mock &
UI_PID=$!

# Supervise: first child to exit wins, then stop the rest.
cleanup() {
  trap - TERM INT
  kill "${VULN_PID}" "${CLEAN_PID}" "${UI_PID}" 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup TERM INT

while kill -0 "${VULN_PID}" 2>/dev/null \
   && kill -0 "${CLEAN_PID}" 2>/dev/null \
   && kill -0 "${UI_PID}" 2>/dev/null; do
  sleep 2
done

echo "a process exited; shutting down" >&2
cleanup
exit 1
