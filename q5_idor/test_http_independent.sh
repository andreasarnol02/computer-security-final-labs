#!/usr/bin/env bash
# Pemeriksaan lepas dari test_attacks.py: klien HTTP terpisah ke server yang berjalan.
# Token dibuat dengan base64 + openssl, tidak memakai fungsi make_token dari simrs_api.py.
set -u
cd "$(dirname "$0")"

if [ "${IN_CONTAINER:-}" != "1" ]; then
  docker ${LAB_DOCKER_CONTEXT:+--context "$LAB_DOCKER_CONTEXT"} run --rm --network none -e IN_CONTAINER=1 \
    -v "$PWD:/lab" -w /lab final-lab:1 bash test_http_independent.sh 2>&1 | tee http_independent_output.txt
  exit "${PIPESTATUS[0]}"
fi

export SIMRS_JWT_KEY="$(openssl rand -hex 32)"
PYTHONDONTWRITEBYTECODE=1 python3 simrs_api.py &
PID=$!
sleep 1

b64u() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }

token() { # token <sub> <role>
  local exp=$(( $(date +%s) + 300 ))
  local h p s
  h=$(printf '{"alg":"HS256","typ":"JWT"}' | b64u)
  p=$(printf '{"sub":"%s","role":"%s","iss":"simrs-idp-lab","aud":"simrs-prescription-api","exp":%s}' "$1" "$2" "$exp" | b64u)
  s=$(printf '%s' "$h.$p" | openssl dgst -sha256 -mac HMAC -macopt "key:$SIMRS_JWT_KEY" -binary | b64u)
  printf '%s.%s.%s' "$h" "$p" "$s"
}

put() { # put <path> <token>
  python3 -I - "$1" "$2" <<'PY'
import sys, urllib.request, urllib.error
req = urllib.request.Request("http://127.0.0.1:18080" + sys.argv[1], method="PUT",
                             data=b'{"dose":"1000 mg 4x1"}',
                             headers={"Authorization": "Bearer " + sys.argv[2]})
try:
    r = urllib.request.urlopen(req, timeout=3); print(r.status, r.read().decode())
except urllib.error.HTTPError as e:
    print(e.code, e.read().decode())
PY
}

ADMIN=$(token A-001 admin)
D2=$(token D-002 doctor)
D1=$(token D-001 doctor)

echo "C1 admin PUT /v1/prescriptions/RX-1002      -> $(put /v1/prescriptions/RX-1002 "$ADMIN")"
echo "C2 admin PUT /v2/prescriptions/RX-1001      -> $(put /v2/prescriptions/RX-1001 "$ADMIN")"
echo "C3 D-002 PUT /v2/prescriptions/RX-1001      -> $(put /v2/prescriptions/RX-1001 "$D2")"
echo "C4 D-001 PUT /v2/prescriptions/RX-1001      -> $(put /v2/prescriptions/RX-1001 "$D1")"

kill "$PID" 2>/dev/null
wait "$PID" 2>/dev/null
exit 0
