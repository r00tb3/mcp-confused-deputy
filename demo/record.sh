#!/bin/sh
# Driver for `make record`. Kept in the repo so demo/demo.cast can be reproduced.
set -e
cd "$(dirname "$0")/.."
PORT=46112

python3 lab/broker.py --mode vuln --port "$PORT" >/dev/null 2>&1 &
BPID=$!
trap 'kill $BPID 2>/dev/null' EXIT
sleep 1.5

echo '$ python3 lab/agent.py --smuggle'
python3 lab/agent.py --base-url "http://127.0.0.1:$PORT" --smuggle 2>&1 \
  | grep -vE '^\[agent\] (connecting|initialized|notifications)' | sed 's/^/  /'

echo
echo "\$ curl -s :$PORT/audit"
curl -s "http://127.0.0.1:$PORT/audit" | python3 -c "
import json, sys
for r in json.load(sys.stdin):
    se = r.get('side_effects') or []
    print('  ' + r['req_id'] + '  ' + r['tool'].ljust(9) + str(sorted(r['params'])))
    for s in se:
        print('              -> ' + s['action'] + ' ok=' + str(s['ok']) + ' :: ' + s['detail'])
"

kill $BPID 2>/dev/null
trap - EXIT

echo
echo '$ python3 verify/verify_priv_esc.py --mode clean'
python3 verify/verify_priv_esc.py --mode clean 2>&1 \
  | grep -E 'PASS|rejected|traversal blocked' | sed 's/^/  /'
