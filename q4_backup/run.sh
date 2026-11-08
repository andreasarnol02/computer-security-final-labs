#!/usr/bin/env bash
# run.sh - satu perintah: `bash run.sh`. Seluruh lab berjalan dalam SATU kontainer (final-lab:1) dan
# keluaran asli, tanpa suntingan, disimpan ke run_output.txt. Kode keluar != 0 bila ada baris
# matriks yang menyimpang dari ekspektasi. Hanya direktori kerja ini yang di-mount dari host.
cd "$(dirname "${BASH_SOURCE[0]}")" || exit 1
SELF=$(basename "${BASH_SOURCE[0]}")

if [ -z "${LAB_IN_CONTAINER:-}" ]; then
  docker ${LAB_DOCKER_CONTEXT:+--context "$LAB_DOCKER_CONTEXT"} run --rm --privileged --network none \
    -e LAB_IN_CONTAINER=1 -e PYTHONDONTWRITEBYTECODE=1 \
    -v "$PWD:/lab" -w /lab final-lab:1 bash "/lab/$SELF" 2>&1 | tee run_output.txt
  exit "${PIPESTATUS[0]}"
fi

# ----------------------------- di dalam kontainer -----------------------------
SB="python3 -B /lab/secure_backup.py"
OVERWRITE="python3 -B /lab/overwrite_simulation.py"
R=/lab_runtime
KEY=$R/keys/lab.key
mkdir -p "$R"

main() {
FAILED=0
ROWS=()
CLEANED=""

title() { printf '\n===== %s =====\n' "$*"; }
# capture CMD...: jalankan, cetak perintah + keluaran + kode keluar; hasilnya ada di $OUT dan $RC
show_cmd() { local a o='$'; for a in "$@"; do [[ $a =~ ^[A-Za-z0-9_./:=%+,@-]+$ ]] && o+=" $a" || o+=" '$a'"; done; printf '%s\n' "$o"; }
capture() {
  show_cmd "$@"
  OUT=$("$@" 2>&1); RC=$?
  [ -n "$OUT" ] && printf '%s\n' "$OUT"
  echo "[exit=$RC]"
}
as_user() { local u=$1; shift; setpriv --reuid="$u" --regid="$u" --clear-groups "$@"; }
manifest() { (cd "$1" && find . -type f ! -name .lab_marker -print0 | sort -z | xargs -0 sha256sum); }
first_line() { printf '%s' "${1%%$'\n'*}"; }
has() { grep -qF -- "$1" <<<"$OUT"; }
# record ID OPERATION ACTUAL_RESULT OK(1/0)
record() {
  local st=YES
  [ "$4" = 1 ] || { st=NO; FAILED=$((FAILED + 1)); }
  ROWS+=("$1 | $2 | $3 | $st")
}
cleanup() {
  [ -n "$CLEANED" ] && return
  CLEANED=1
  title "Cleanup: remove immutable flag, unmount vault"
  cd /
  chattr -R -i "$R/vault" 2>&1
  echo "i flags remaining in vault: $(lsattr -R "$R/vault" 2>/dev/null | awk 'NF==2 {print $1}' | grep -c i)"
  umount "$R/vault" && echo "umount vault: SUCCESS" || echo "umount vault: FAILED"
  echo "active loop devices: $(losetup -a | wc -l)"
}
trap cleanup EXIT

title "0. Environment"
uname -sr
python3 --version
openssl version
python3 -c "import cryptography; print('cryptography', cryptography.__version__)"
ls -ld /lab; id

title "0. Setup: 64 MB ext4 vault (loop mount inside the container)"
mkdir -p "$R/keys" "$R/perm_tests" "$R/vault" && chmod 700 "$R/keys"
dd if=/dev/zero of="$R/vault.img" bs=1M count=64 status=none && mkfs.ext4 -q -F "$R/vault.img"
mount -o loop "$R/vault.img" "$R/vault" || { echo "FAILED loop mount"; return 1; }
touch "$R/vault/.lab_marker"
findmnt -no TARGET,FSTYPE,SOURCE "$R/vault"
df -hT "$R/vault" | tail -1

title "0. Setup: users backupop (uid 1001) and other (uid 1002)"
useradd -m -u 1001 -s /bin/bash backupop && useradd -m -u 1002 -s /bin/bash other
id backupop; id other

title "0. Setup: synthetic EHR data, old flat backup, key"
mkdir -p "$R/ehr"
awk 'BEGIN{print "id,name,birth_date,blood_type"; for(i=1;i<=150;i++) printf "P%04d,Pasien-%04d,19%02d-%02d-%02d,%s\n",i,i,50+i%50,1+i%12,1+i%28,substr("ABOA",1+i%4,1)}' > "$R/ehr/patients.csv"
awk 'BEGIN{print "visit_id,id,date,clinic"; for(i=1;i<=300;i++) printf "K%05d,P%04d,2026-%02d-%02d,Poli-%d\n",i,1+i%150,1+i%12,1+i%28,1+i%5}' > "$R/ehr/visits.csv"
awk 'BEGIN{print "lab_id,id,test,value"; for(i=1;i<=200;i++) printf "L%05d,P%04d,Tes-%d,%.2f\n",i,1+i%150,1+i%7,(i*37%1000)/10}' > "$R/ehr/lab_results.csv"
awk 'BEGIN{print "prescription_id,id,drug,dose"; for(i=1;i<=250;i++) printf "R%05d,P%04d,Obat-%d,%dmg\n",i,1+i%150,1+i%9,50*(1+i%6)}' > "$R/ehr/prescriptions.csv"
awk 'BEGIN{print "bill_id,id,amount_idr"; for(i=1;i<=180;i++) printf "T%05d,P%04d,%d\n",i,1+i%150,10000*(1+i%40)}' > "$R/ehr/billing.csv"
echo "lab marker - synthetic data" > "$R/ehr/.lab_marker"
chmod 755 "$R/ehr"; chmod 644 "$R/ehr"/*
# "backup datar gaya lama": salinan biasa, izin normal, milik backupop, dianggap terpasang sebagai share jaringan
mkdir -p "$R/flat_backup" && cp -a "$R/ehr/." "$R/flat_backup/"
chown -R backupop:backupop "$R/flat_backup"
head -c 32 /dev/urandom > "$KEY" && chmod 0400 "$KEY"
manifest "$R/ehr" > "$R/manifest_original.txt"
NFILES=$(wc -l < "$R/manifest_original.txt")
echo "source files (without .lab_marker): $NFILES"; ls -l "$R/ehr" "$R/flat_backup"; stat -c '%a %U %n' "$KEY"

title "A1. openssl enc -aes-256-gcm"
capture openssl enc -aes-256-gcm -pbkdf2 -pass pass:example-not-the-real-key -in "$R/ehr/patients.csv" -out /dev/null
if [ "$RC" -ne 0 ] && grep -qi aead <<<"$OUT"; then ok=1; else ok=0; fi
record A1 "openssl enc -aes-256-gcm" "exit=$RC: $(first_line "$OUT")" $ok

title "A2. AES-256-GCM known-answer test (test_gcm_kat.py)"
capture python3 -B /lab/test_gcm_kat.py
if [ "$RC" -eq 0 ] && has PASS; then ok=1; else ok=0; fi
record A2 "test_gcm_kat.py (McGrew-Viega TC14)" "exit=$RC: $(tail -n1 <<<"$OUT")" $ok

title "B1. Backup by root into the vault: permissions and immutable flag"
capture $SB backup "$R/ehr" "$R/vault/archive" --key-file "$KEY"
BK_RC=$RC
ARCHIVE=$(ls "$R"/vault/archive/*.tar.gz.enc 2>/dev/null | head -n1)
capture stat -c '%a %U %n' "$ARCHIVE" "$ARCHIVE.sha256" "$R/vault/archive"
MODE=$(stat -c %a "$ARCHIVE")
capture lsattr "$ARCHIVE" "$ARCHIVE.sha256"
FLAG=$(lsattr "$ARCHIVE" | awk '{print $1}')
capture bash -c 'cd "$1" && sha256sum -c "$2"' bash "$R/vault/archive" "$(basename "$ARCHIVE").sha256"
if [ "$BK_RC" -eq 0 ] && [ "$MODE" = 400 ] && [[ "$FLAG" == *i* ]]; then ok=1; else ok=0; fi
record B1 "backup (root) -> stat + lsattr" "mode=$MODE owner=$(stat -c %U "$ARCHIVE") lsattr=$FLAG" $ok

title "B2. Restore (round trip): sha256 of every file equals the original"
capture $SB verify "$ARCHIVE" --key-file "$KEY"
capture $SB restore "$ARCHIVE" "$R/restored_b2" --key-file "$KEY"
manifest "$R/restored_b2/ehr" > "$R/manifest_b2.txt"
if diff "$R/manifest_original.txt" "$R/manifest_b2.txt" >/dev/null && [ "$RC" -eq 0 ]; then ok=1; else ok=0; fi
echo "sha256 comparison: $(wc -l < "$R/manifest_b2.txt") restored files vs $NFILES original -> $([ "$ok" = 1 ] && echo SAME || echo DIFFERENT)"
record B2 "restore + sha256sum of all files" "$NFILES files, sha256 $([ "$ok" = 1 ] && echo all same || echo DIFFERENT)" $ok

flip_byte() {
  python3 -B -c 'import sys; p, o = sys.argv[1], int(sys.argv[2]); b = bytearray(open(p, "rb").read()); b[o] ^= 1; open(p, "wb").write(b); print(f"byte offset {o} of {len(b)} flipped (lowest bit)")' "$1" "$2"
}

title "C1. One byte flipped in a COPY of the archive -> verify must reject"
SIZE=$(stat -c %s "$ARCHIVE")
cp "$ARCHIVE" "$R/perm_tests/copy_c1_body.enc"; chmod 600 "$R/perm_tests/copy_c1_body.enc"
flip_byte "$R/perm_tests/copy_c1_body.enc" $((SIZE / 2))
capture $SB verify "$R/perm_tests/copy_c1_body.enc" --key-file "$KEY"
C1A=$RC
cp "$ARCHIVE" "$R/perm_tests/copy_c1_hdr.enc"; chmod 600 "$R/perm_tests/copy_c1_hdr.enc"
echo "(extra) flip one byte in the header timestamp, which is protected by AAD:"
flip_byte "$R/perm_tests/copy_c1_hdr.enc" 6
capture $SB verify "$R/perm_tests/copy_c1_hdr.enc" --key-file "$KEY"
C1B=$RC
capture $SB verify "$ARCHIVE" --key-file "$KEY"
if [ "$C1A" -eq 3 ] && [ "$C1B" -eq 3 ] && [ "$RC" -eq 0 ]; then ok=1; else ok=0; fi
record C1 "verify a copy with 1 byte flipped" "body: exit=$C1A; header/AAD: exit=$C1B; original archive: exit=$RC" $ok

title "C2. Wrong key -> verify must reject"
head -c 32 /dev/urandom > "$R/keys/wrong.key"; chmod 0400 "$R/keys/wrong.key"
capture $SB verify "$ARCHIVE" --key-file "$R/keys/wrong.key"
if [ "$RC" -eq 3 ]; then ok=1; else ok=0; fi
record C2 "verify with wrong key" "exit=$RC: $(first_line "$OUT")" $ok

title "C3. Key violates the rules -> denied (exit 2)"
head -c 32 /dev/urandom > "$R/keys/mode644.key"; chmod 0644 "$R/keys/mode644.key"
capture $SB verify "$ARCHIVE" --key-file "$R/keys/mode644.key"; C3A=$RC
head -c 31 /dev/urandom > "$R/keys/short.key"; chmod 0400 "$R/keys/short.key"
capture $SB verify "$ARCHIVE" --key-file "$R/keys/short.key"; C3B=$RC
mkdir -p "$R/perm_tests/dest_c3"; head -c 32 /dev/urandom > "$R/perm_tests/dest_c3/k.key"; chmod 0400 "$R/perm_tests/dest_c3/k.key"
capture $SB backup "$R/ehr" "$R/perm_tests/dest_c3" --key-file "$R/perm_tests/dest_c3/k.key"; C3C=$RC
echo "dest_c3 contents after the denial: $(ls "$R/perm_tests/dest_c3" | tr '\n' ' ')"
if [ "$C3A" -eq 2 ] && [ "$C3B" -eq 2 ] && [ "$C3C" -eq 2 ] && [ "$(ls "$R/perm_tests/dest_c3")" = "k.key" ]; then ok=1; else ok=0; fi
record C3 "key mode 0644 / length 31 / inside dest_dir" "exit=$C3A / exit=$C3B / exit=$C3C" $ok

title "D1. User other (uid 1002) tries to overwrite the 0400 archive"
capture as_user other bash -c 'echo OVERWRITE > "$1"' bash "$ARCHIVE"; D1A=$RC; D1A_OUT=$OUT
capture as_user other stat "$ARCHIVE"; D1S=$RC
echo "(control) the 0500 archive directory alone already blocks traversal; separate the file-mode effect:"
echo "control data" > "$R/perm_tests/d1_control.txt"; chmod 0400 "$R/perm_tests/d1_control.txt"
stat -c '%a %U %n' "$R/perm_tests/d1_control.txt"
capture as_user other bash -c 'echo OVERWRITE > "$1"' bash "$R/perm_tests/d1_control.txt"; D1B=$RC
if [ "$D1A" -ne 0 ] && [ "$D1B" -ne 0 ] && grep -q 'Permission denied' <<<"$D1A_OUT" && has 'Permission denied'; then ok=1; else ok=0; fi
record D1 "other overwrites 0400 archive" "archive: Permission denied (exit=$D1A; stat as other exit=$D1S, dir 0500 blocks traversal); control 0400 file in dir 755: Permission denied (exit=$D1B)" $ok

title "D2. Owner (backupop) runs chmod u+w then overwrites a 0400 file WITHOUT the immutable flag"
F2=$R/perm_tests/d2_owned_by_backupop.txt
echo "original content D2" > "$F2"; chown backupop:backupop "$F2"; chmod 0400 "$F2"
stat -c '%a %U %n' "$F2"; lsattr "$F2"
capture as_user backupop bash -c 'echo OVERWRITE > "$1"' bash "$F2"; D2A=$RC
capture as_user backupop bash -c 'chmod u+w "$1" && echo OVERWRITTEN-BY-OWNER > "$1"' bash "$F2"; D2B=$RC
echo "content now: $(cat "$F2")"
if [ "$D2A" -ne 0 ] && [ "$D2B" -eq 0 ] && [ "$(cat "$F2")" = "OVERWRITTEN-BY-OWNER" ]; then ok=1; else ok=0; fi
record D2 "backupop: chmod u+w then overwrite (0400, no +i)" "without chmod: exit=$D2A; after chmod u+w: exit=$D2B, content changed" $ok

title "D3. Root overwrites a 0400 file WITHOUT the immutable flag"
F3=$R/perm_tests/d3_0400.txt
echo "original content D3" > "$F3"; chown backupop:backupop "$F3"; chmod 0400 "$F3"
stat -c '%a %U %n' "$F3"; lsattr "$F3"
capture bash -c 'echo OVERWRITTEN-BY-ROOT > "$1"' bash "$F3"; D3=$RC
echo "content now: $(cat "$F3"); mode: $(stat -c %a "$F3")"
if [ "$D3" -eq 0 ] && [ "$(cat "$F3")" = "OVERWRITTEN-BY-ROOT" ]; then ok=1; else ok=0; fi
record D3 "root overwrites 0400 without +i" "exit=$D3, content changed, mode still $(stat -c %a "$F3")" $ok

title "D4. Root tries to overwrite and rm the 0400 + immutable archive"
SHA_BEFORE=$(sha256sum "$ARCHIVE" | awk '{print $1}')
lsattr "$ARCHIVE"
capture bash -c 'echo OVERWRITE > "$1"' bash "$ARCHIVE"; D4A=$RC; D4A_OUT=$OUT
capture rm "$ARCHIVE"; D4B=$RC; D4B_OUT=$OUT
SHA_AFTER=$(sha256sum "$ARCHIVE" 2>/dev/null | awk '{print $1}')
echo "sha256 before=$SHA_BEFORE"; echo "sha256 after=$SHA_AFTER"
if [ "$D4A" -ne 0 ] && [ "$D4B" -ne 0 ] && grep -q 'Operation not permitted' <<<"$D4A_OUT" && grep -q 'Operation not permitted' <<<"$D4B_OUT" && [ "$SHA_BEFORE" = "$SHA_AFTER" ]; then ok=1; else ok=0; fi
record D4 "root: overwrite and rm 0400+i archive" "overwrite: Operation not permitted (exit=$D4A); rm: Operation not permitted (exit=$D4B); archive intact" $ok

title "D5. Root runs chattr -i on a test COPY then overwrites (not the real archive)"
mkdir -p "$R/vault/test_d5"; F5=$R/vault/test_d5/test_copy.enc
cp "$ARCHIVE" "$F5"; chmod 0400 "$F5"; chattr +i "$F5"; lsattr "$F5"
SHA5A=$(sha256sum "$F5" | awk '{print $1}')
capture bash -c 'echo OVERWRITE > "$1"' bash "$F5"; D5A=$RC
capture chattr -i "$F5"; D5B=$RC
lsattr "$F5"
capture bash -c 'echo OVERWRITTEN-BY-ROOT-AFTER-CHATTR > "$1"' bash "$F5"; D5C=$RC
SHA5B=$(sha256sum "$F5" | awk '{print $1}')
echo "copy sha256 before=$SHA5A"; echo "copy sha256 after=$SHA5B"
chattr -i "$F5" 2>/dev/null; rm -f "$F5"; rmdir "$R/vault/test_d5"
if [ "$D5A" -ne 0 ] && [ "$D5B" -eq 0 ] && [ "$D5C" -eq 0 ] && [ "$SHA5A" != "$SHA5B" ]; then ok=1; else ok=0; fi
record D5 "root: chattr -i on a test copy then overwrite" "denied while +i (exit=$D5A); chattr -i exit=$D5B; overwrite exit=$D5C, sha256 changed" $ok

title "E1. backupop runs overwrite_simulation.py: production, flat backup, vault"
chown -R backupop:backupop "$R/ehr"
ls -ld "$R/ehr"; stat -c '%a %U %n' "$R/vault" "$R/vault/archive"
capture as_user backupop $OVERWRITE "$R/ehr" "$R/flat_backup" "$R/vault"
E1_RC=$RC
field_value() { grep "^$1:" <<<"$OUT" | sed -E "s/.*$2=([0-9]+).*/\1/"; }
EHR_DONE=$(field_value "$R/ehr" overwritten); EHR_REFUSED=$(field_value "$R/ehr" refused)
FLAT_DONE=$(field_value "$R/flat_backup" overwritten); FLAT_REFUSED=$(field_value "$R/flat_backup" refused)
VAULT_DONE=$(field_value "$R/vault" overwritten); VAULT_REFUSED=$(field_value "$R/vault" refused)
echo "NOTE: the vault refusal here is EACCES (Permission denied) = DAC: owned by root + archive directory 0500 cannot be entered by backupop. The i flag would produce EPERM (Operation not permitted) and only matters against root (see D4/D5)."
echo "archive after E1:"; (cd "$R/vault/archive" && sha256sum -c "$(basename "$ARCHIVE").sha256"); lsattr "$ARCHIVE"
if [ "$E1_RC" -eq 0 ] && [ "$EHR_DONE" = "$NFILES" ] && [ "$EHR_REFUSED" = 0 ] && [ "$FLAT_DONE" = "$NFILES" ] && [ "$FLAT_REFUSED" = 0 ] && [ "$VAULT_DONE" = 0 ] && [ "${VAULT_REFUSED:-0}" -ge 1 ]; then ok=1; else ok=0; fi
record E1 "backupop: overwrite simulation on 3 directories" "ehr overwritten=$EHR_DONE/refused=$EHR_REFUSED; flat_backup overwritten=$FLAT_DONE/refused=$FLAT_REFUSED; vault overwritten=$VAULT_DONE/refused=$VAULT_REFUSED" $ok

title "E2. Production corrupted, restore from the vault, measure time"
manifest "$R/ehr" > "$R/manifest_corrupted.txt"
CORRUPTED=$(diff "$R/manifest_original.txt" "$R/manifest_corrupted.txt" | grep -c '^<')
echo "production: $CORRUPTED of $NFILES files have a sha256 different from the original"
sort "$R/manifest_corrupted.txt" | head -n2
T0=$(date +%s.%N)
capture $SB restore "$ARCHIVE" "$R/restored_e2" --key-file "$KEY"
T1=$(date +%s.%N)
ELAPSED=$(awk -v a="$T0" -v b="$T1" 'BEGIN{printf "%.3f", b - a}')
manifest "$R/restored_e2/ehr" > "$R/manifest_e2.txt"
if diff "$R/manifest_original.txt" "$R/manifest_e2.txt" >/dev/null; then RESTORED=same; else RESTORED=DIFFERENT; fi
echo "restore time (restore, vault source): ${ELAPSED} seconds for $(du -sb "$R/restored_e2/ehr" | awk '{print $1}') bytes of synthetic data"
echo "sha256 restored vs original: $RESTORED ($(wc -l < "$R/manifest_e2.txt") files)"
if [ "$CORRUPTED" = "$NFILES" ] && [ "$RC" -eq 0 ] && [ "$RESTORED" = same ]; then ok=1; else ok=0; fi
record E2 "production corrupted then restore from vault" "corrupted $CORRUPTED/$NFILES files; restored sha256 $RESTORED; restore time ${ELAPSED} seconds" $ok

cleanup

title "TEST MATRIX (actual results)"
echo "ID | Operation | Actual result | As expected"
printf '%s\n' "${ROWS[@]}"
echo "Deviating rows: $FAILED of ${#ROWS[@]}"
[ "$FAILED" -eq 0 ]
}

main 2>&1 | tee "$R/internal_output.txt"
RC_MAIN=${PIPESTATUS[0]}

echo
echo "===== Extra check: the real key does not leak into the output ====="
python3 -B - "$KEY" "$R/internal_output.txt" <<'PY'
import base64, hashlib, sys
k, t = open(sys.argv[1], "rb").read(), open(sys.argv[2], "rb").read()
forms = {"raw": k, "hex": k.hex().encode(), "HEX": k.hex().upper().encode(),
         "base64": base64.b64encode(k), "base64url": base64.urlsafe_b64encode(k)}
leaked = [n for n, v in forms.items() if v in t]
print(f"output checked: {len(t)} bytes, sha256={hashlib.sha256(t).hexdigest()}")
print("Z1 | real key (raw/hex/base64) in output | " + (f"FOUND: {leaked}" if leaked else "not found") + " | " + ("NO" if leaked else "YES"))
sys.exit(1 if leaked else 0)
PY
RC_LEAK=$?
if [ "$RC_MAIN" -eq 0 ] && [ "$RC_LEAK" -eq 0 ]; then echo "FINAL STATUS: all rows as expected"; exit 0; fi
echo "FINAL STATUS: deviations found (matrix=$RC_MAIN, leak=$RC_LEAK)"
exit 1
