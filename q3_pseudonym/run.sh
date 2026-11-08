#!/usr/bin/env bash
# run.sh - satu perintah: data sintetis -> pseudonimisasi -> k/l -> uji T1-T9, semua di satu kontainer.
# Kunci HMAC dibangkitkan acak di dalam kontainer dan hanya hidup sebagai variabel lingkungan proses;
# tidak pernah ditulis ke berkas dan tidak pernah dicetak. Keluaran asli di-tee ke run_output.txt.
set -u
cd "$(dirname "${BASH_SOURCE[0]}")" || exit 1

if [ "${IN_CONTAINER:-}" != "1" ]; then
  exec docker ${LAB_DOCKER_CONTEXT:+--context "$LAB_DOCKER_CONTEXT"} run --rm --network none -e IN_CONTAINER=1 \
    -v "$PWD:/lab" -w /lab final-lab:1 bash run.sh
fi

export PYTHONDONTWRITEBYTECODE=1
PSEUDO_KEY_HEX="$(openssl rand -hex 32)"
export PSEUDO_KEY_HEX

stages() {
  echo "== 1. Synthetic data (generate_ehr.py, seed 2026) =="
  python3 generate_ehr.py || return 1
  echo
  echo "== 2. First three rows of the raw data (synthetic) =="
  head -n 4 ehr_raw.csv
  local report rc
  report="$(python3 pseudonymize.py 2>&1)"
  rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "$report"
    return "$rc"
  fi
  echo
  echo "== 3. First three rows of the pseudonymized data =="
  head -n 4 ehr_pseudonymized.csv
  echo
  echo "== 4. k and l measures (K_MIN=5) and classes at homogeneity risk =="
  echo "$report"
  echo
  echo "== 5. Tests T1-T9 =="
  python3 verify_output.py
}

stages 2>&1 | tee run_output.txt
rc=${PIPESTATUS[0]}

# Pemeriksaan akhir: kunci tidak boleh ada di berkas mana pun (termasuk run_output.txt).
if grep -rqiF -- "$PSEUDO_KEY_HEX" .; then
  message="[FAIL] HMAC key DETECTED in a file in the working directory"
  rc=1
else
  message="[PASS] HMAC key not found in any file in the working directory (including run_output.txt)"
fi
echo "$message" | tee -a run_output.txt
exit "$rc"
