#!/usr/bin/env bash
# Skenario lengkap audit IoMT; dijalankan DI DALAM kontainer oleh run.sh.
# Tanpa -e: beberapa langkah SENGAJA exit != 0 dan diperiksa manual di bawah.
set -uo pipefail
failed=0

cleanup() {
    if [ -n "${LAB_PID:-}" ]; then
        kill "$LAB_PID" 2>/dev/null
        wait "$LAB_PID" 2>/dev/null
    fi
    LAB_PID=""
}
trap cleanup EXIT

echo "================================================================"
echo "A. Baseline audit (before remediation)"
echo "================================================================"
python iomt_lab.py &
LAB_PID=$!
sleep 0.5
python audit_iomt.py --cidr 127.0.10.0/28 --authorized --json-out report_baseline.json
code_a=$?
echo ">>> audit_iomt.py (baseline) exit code: $code_a"

echo
echo "================================================================"
echo "B. Independent ORACLE: nmap (baseline) vs report_baseline.json"
echo "================================================================"
nmap -Pn -n -p 23,80,443,8080 --open -oG nmap_baseline.gnmap 127.0.10.0/28
python compare_nmap.py report_baseline.json nmap_baseline.gnmap
code_b=$?
[ "$code_b" -ne 0 ] && failed=1
cleanup

echo
echo "================================================================"
echo "C. Audit after --hardened (remediation on .11) + nmap oracle"
echo "================================================================"
python iomt_lab.py --hardened &
LAB_PID=$!
sleep 0.5
python audit_iomt.py --cidr 127.0.10.0/28 --authorized --json-out report_hardened.json
code_c=$?
echo ">>> audit_iomt.py (hardened) exit code: $code_c"
nmap -Pn -n -p 23,80,443,8080 --open -oG nmap_hardened.gnmap 127.0.10.0/28
python compare_nmap.py report_hardened.json nmap_hardened.gnmap
code_c_compare=$?
[ "$code_c_compare" -ne 0 ] && failed=1
cleanup

echo
echo ">>> Before/after summary (number of findings per risk level):"
python -c "
import json


def count_by_risk(path):
    counts = {}
    for t in json.load(open(path)):
        counts[t['risk']] = counts.get(t['risk'], 0) + 1
    return counts


before, after = count_by_risk('report_baseline.json'), count_by_risk('report_hardened.json')
for level in ('CRITICAL', 'HIGH', 'MEDIUM'):
    print(f'  {level}: before={before.get(level, 0)} -> after={after.get(level, 0)}')
"
if [ "$code_c" -ne 0 ]; then
    echo ">>> FAILED: audit after hardening should exit 0 (no CRITICAL)."
    failed=1
fi

echo
echo "================================================================"
echo "D. Negative controls for the scope guard (must not open any socket)"
echo "================================================================"
set +e
python audit_iomt.py --cidr 127.0.10.0/28
k1=$?
echo ">>> without --authorized -> exit code: $k1"
python audit_iomt.py --cidr 8.8.8.0/24 --authorized
k2=$?
echo ">>> public network 8.8.8.0/24 --authorized -> exit code: $k2"
python audit_iomt.py --cidr 10.0.0.0/8 --authorized
k3=$?
echo ">>> prefix too wide 10.0.0.0/8 --authorized -> exit code: $k3"
set -e
for k in "$k1" "$k2" "$k3"; do
    [ "$k" -ne 2 ] && failed=1
done

echo
echo "================================================================"
if [ "$failed" -eq 0 ]; then
    echo "SCENARIO DONE: all checks as expected."
else
    echo "SCENARIO DONE WITH PROBLEMS: check the log above."
fi
exit "$failed"
