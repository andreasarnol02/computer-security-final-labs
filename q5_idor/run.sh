#!/usr/bin/env bash
# Satu perintah, satu kontainer tanpa jaringan. Kunci dibuat di dalam kontainer agar
# tidak muncul di argv host, tidak pernah dicetak, dan hilang bersama kontainer.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

docker ${LAB_DOCKER_CONTEXT:+--context "$LAB_DOCKER_CONTEXT"} run --rm --network none -v "$PWD:/lab" -w /lab final-lab:1 bash -c '
set -uo pipefail
export PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
export SIMRS_JWT_KEY="$(openssl rand -hex 32)"

{
  echo "== Environment =="
  python3 --version
  openssl version
  echo
  echo "== test_primitives.py =="
  python3 test_primitives.py
  rc_primitives=$?
  echo
  echo "== test_attacks.py =="
  python3 test_attacks.py
  rc_attacks=$?
  echo
  echo "exit test_primitives=$rc_primitives test_attacks=$rc_attacks"
  exit $(( rc_primitives != 0 || rc_attacks != 0 ))
} 2>&1 | tee run_output.txt
rc=${PIPESTATUS[0]}

# Pemeriksaan kebocoran: kunci tidak boleh muncul di berkas keluaran.
if grep -qF -- "$SIMRS_JWT_KEY" run_output.txt; then
  message="FAIL: key appears in the output"
else
  message="PASS: key (${#SIMRS_JWT_KEY} bytes) does not appear in the output"
fi
echo "$message" | tee -a run_output.txt
echo "exit run.sh=$rc" | tee -a run_output.txt
exit "$rc"
'
