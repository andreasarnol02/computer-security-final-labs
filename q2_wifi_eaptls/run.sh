#!/usr/bin/env bash
# Simulasi Wi-Fi Enterprise (EAP-TLS) - satu perintah:  bash run.sh
# Semua langkah berjalan di SATU kontainer Docker tanpa jaringan (--network none).
# Handshake EAP-TLS nyata: eapol_test (klien/supplicant) <-> hostapd (server RADIUS) via loopback.
# Keluaran ASLI disimpan tanpa suntingan ke run_output.txt. Semua nama/sertifikat sintetis.
set -euo pipefail
cd "$(dirname "$0")"

# ---------------------------------------------------------------- di host: masuk kontainer
if [ -z "${LAB_IN_CONTAINER:-}" ]; then
  set +e
  docker ${LAB_DOCKER_CONTEXT:+--context "$LAB_DOCKER_CONTEXT"} run --rm --network none \
    -v "$PWD:/lab" -w /lab -e LAB_IN_CONTAINER=1 final-lab:1 bash run.sh 2>&1 | tee run_output.txt
  exit "${PIPESTATUS[0]}"
fi

# ---------------------------------------------------------------- di dalam kontainer
umask 022
rm -rf evidence
mkdir -p evidence
FAILED=0
declare -a CHECKS TABLE
FMT='%-9s| %-22s| %-26s| %-17s| %-18s| %s'

separator() { printf '\n%s\n' "============================================================================"; }
heading()   { separator; printf '%s\n' "$*"; printf '%s\n' "============================================================================"; }
run_cmd() {    # cetak perintah, jalankan (kegagalan diizinkan), simpan kode keluar di RC
  echo "\$ $*"
  set +e; "$@" 2>&1; RC=$?; set -e
}
expect() {     # $1 deskripsi  $2 kode yang diharapkan ("0" atau "nonzero")  $3 kode sebenarnya
  local ok=0
  if [ "$2" = "0" ]; then
    if [ "$3" -eq 0 ]; then ok=1; fi
  else
    if [ "$3" -ne 0 ]; then ok=1; fi
  fi
  if [ "$ok" -eq 1 ]; then
    CHECKS+=("MATCH    | $1 (code=$3, expected: $2)")
  else
    CHECKS+=("MISMATCH | $1 (code=$3, expected: $2)"); FAILED=$((FAILED + 1))
  fi
}

heading "ENVIRONMENT INFO (isolated container: --network none)"
date -u '+Time (UTC): %Y-%m-%d %H:%M:%S'
echo "Kernel     : $(uname -sr)"
echo "OpenSSL    : $(openssl version)"
echo "Python     : $(python3 --version)"
echo "Supplicant : $(wpa_supplicant -v 2>&1 | head -n1)"
echo "hostapd    : $(hostapd -v 2>&1 | head -n1)"
echo "Interfaces : $(ls /sys/class/net | tr '\n' ' ')(loopback only = no network)"

# ================================================================= STEP 0
heading "STEP 0 - Build the synthetic PKI and the secure profile"
run_cmd bash make_pki.sh;              expect "make_pki.sh" 0 "$RC"
run_cmd python3 generate_profile.py;   expect "generate_profile.py" 0 "$RC"
run_cmd cat wpa_supplicant.conf

# ================================================================= STEP 1
heading "STEP 1 - Independent oracle: openssl verify against the hospital CA"
echo "Identity of the two CAs (IDENTICAL name, different key):"
for ca in rs-root-ca rogue-ca; do
  echo "[$ca]"
  openssl x509 -in "pki/$ca.pem" -noout -subject -fingerprint -sha256
  openssl x509 -in "pki/$ca.pem" -noout -ext subjectKeyIdentifier | tail -n1 | sed 's/^ */  SKI: /'
done
echo
for s in server-legit server-rogue server-wrongname; do
  run_cmd openssl verify -CAfile pki/rs-root-ca.pem "pki/$s.pem"
  case $s in
    server-legit)     expect "verify chain of legit server" 0 "$RC" ;;
    server-rogue)     expect "verify chain of rogue server (identical CA name) MUST fail" nonzero "$RC" ;;
    server-wrongname) expect "verify chain of wrong-name server (real CA) passes chain" 0 "$RC" ;;
  esac
  echo
done
echo "Host NAME check (same as domain_match in the supplicant):"
run_cmd openssl verify -CAfile pki/rs-root-ca.pem -verify_hostname radius.rs-sehat.example pki/server-legit.pem
expect "verify_hostname legit server" 0 "$RC"
run_cmd openssl verify -CAfile pki/rs-root-ca.pem -verify_hostname radius.rs-sehat.example pki/server-wrongname.pem
expect "verify_hostname wrong-name server MUST fail" nonzero "$RC"

# ================================================================= STEP 2
heading "STEP 2 - Profile audit (audit_profile.py)"
# Profil lemah: tanpa ca_cert, tanpa domain_match, PMF dimatikan.
sed -e '/^\s*ca_cert=/d' -e '/^\s*domain_match=/d' \
    -e 's/^\(\s*\)ieee80211w=2/\1ieee80211w=0/' wpa_supplicant.conf > profile_weak.conf
# Profil untuk S4: ca_cert ada, tetapi domain_match dihapus.
sed -e '/^\s*domain_match=/d' wpa_supplicant.conf > profile_no_domain.conf
chmod 600 profile_weak.conf profile_no_domain.conf
echo "\$ diff wpa_supplicant.conf profile_weak.conf   (difference secure -> weak profile)"
diff wpa_supplicant.conf profile_weak.conf || true
echo
run_cmd python3 audit_profile.py wpa_supplicant.conf
echo "Exit code of SECURE profile audit: $RC"
expect "secure profile audit passes" 0 "$RC"
echo
run_cmd python3 audit_profile.py profile_weak.conf
echo "Exit code of WEAK profile audit  : $RC"
expect "weak profile audit MUST fail" nonzero "$RC"
echo
echo "Extra control - profile for S4 (ca_cert present, domain_match removed):"
run_cmd python3 audit_profile.py profile_no_domain.conf
echo "Exit code of audit without domain_match: $RC"
expect "audit of profile without domain_match MUST fail (R5)" nonzero "$RC"

# ================================================================= STEP 3
heading "STEP 3 - The wpa_supplicant parser itself as an oracle"
rm -rf /run/wpa_supplicant
echo "\$ timeout 3 wpa_supplicant -c wpa_supplicant.conf -i lo -D wired -d   (full output: evidence/parser_ok.log)"
set +e; timeout 3 wpa_supplicant -c wpa_supplicant.conf -i lo -D wired -d > evidence/parser_ok.log 2>&1; RC=$?; set -e
echo "Exit code: $RC (124 = stopped by the 3 second timeout, not a configuration error)"
echo "--- Configuration reading section:"
sed -n '/^Reading configuration file/,/^ *id=0 ssid=/p' evidence/parser_ok.log
echo "--- Number of 'Failed to read or parse configuration' lines: $(grep -c 'Failed to read or parse configuration' evidence/parser_ok.log || true)"
echo "--- After the configuration is accepted, behaviour of the 'wired' driver on lo (observed as is):"
grep -E 'Management frame protection|Could not set WPA suites|Failed to get scan results|CTRL-EVENT-TERMINATING' evidence/parser_ok.log || true
echo "(The messages above appear because lo has no real AP/scan and the profile requires PMF; they are not parser errors.)"
if grep -q 'Failed to read or parse configuration' evidence/parser_ok.log; then P_RC=1; else P_RC=0; fi
expect "wpa_supplicant parser accepts the secure configuration (no read-failure message)" 0 "$P_RC"
echo
sed 's/^\(\s*\)ca_cert=/\1ca_certt=/' wpa_supplicant.conf > evidence/typo.conf
chmod 600 evidence/typo.conf
echo "\$ diff wpa_supplicant.conf evidence/typo.conf   (negative control: ca_certt typo)"
diff wpa_supplicant.conf evidence/typo.conf || true
rm -rf /run/wpa_supplicant
echo "\$ timeout 3 wpa_supplicant -c evidence/typo.conf -i lo -D wired -d"
set +e; timeout 3 wpa_supplicant -c evidence/typo.conf -i lo -D wired -d > evidence/parser_typo.log 2>&1; RC=$?; set -e
echo "Exit code: $RC"
grep -E "unknown network field|failed to parse network block|Failed to read or parse configuration" evidence/parser_typo.log || true
if grep -q "unknown network field 'ca_certt'" evidence/parser_typo.log; then T_RC=0; else T_RC=1; fi
expect "wpa_supplicant parser rejects the ca_certt typo (unknown network field)" 0 "$T_RC"
rm -rf /run/wpa_supplicant

# ================================================================= STEP 4
heading "STEP 4 - Real EAP-TLS handshake (eapol_test <-> hostapd), one hostapd process per scenario"
PORT=18120

scenario() {  # id  server-cert  client-profile  expected  server-label  profile-label  reason-pattern
  local id=$1 srv=$2 profile=$3 expected=$4 srv_label=$5 profile_label=$6 pattern=$7
  local d="evidence/$id" hp result reason matched
  PORT=$((PORT + 1))
  mkdir -p "$d"
  echo '* TLS' > "$d/eap_user"
  echo '127.0.0.1/32 secretlab' > "$d/radius_clients"
  cat > "$d/hostapd.conf" <<EOF
driver=none
logger_stdout=-1
logger_stdout_level=2
eap_server=1
eap_user_file=$PWD/$d/eap_user
ca_cert=$PWD/pki/rs-root-ca.pem
server_cert=$PWD/pki/$srv.pem
private_key=$PWD/pki/$srv.key
radius_server_clients=$PWD/$d/radius_clients
radius_server_auth_port=$PORT
EOF
  cp "$profile" "$d/client.conf"; chmod 600 "$d/client.conf"

  separator
  echo "$id | Server: $srv_label | Client profile: $profile_label | Expected: $expected"
  echo "--- hostapd (RADIUS+EAP server) uses these files:"
  grep -E '^(ca_cert|server_cert|private_key|radius_server_auth_port)=' "$d/hostapd.conf"
  echo "--- client profile ($profile), relevant EAP lines:"
  grep -E '^\s*(eap|ca_cert|domain_match|client_cert|private_key|phase1)=' "$profile" || true

  hostapd -dd "$d/hostapd.conf" > "$d/hostapd.log" 2>&1 &
  hp=$!
  for _ in $(seq 1 100); do grep -q 'Setup of interface done' "$d/hostapd.log" && break; sleep 0.1; done
  if ! grep -q 'Setup of interface done' "$d/hostapd.log"; then
    echo "ERROR: hostapd not ready (see $d/hostapd.log)"
    kill "$hp" 2>/dev/null || true; wait "$hp" 2>/dev/null || true
    TABLE+=("$(printf "$FMT" "$id" "$srv_label" "$profile_label" "ERROR" "NO" "hostapd not ready")")
    FAILED=$((FAILED + 1)); return 0
  fi
  echo "--- hostapd ready (pid $hp, UDP 127.0.0.1:$PORT)"
  echo "\$ eapol_test -c $profile -a 127.0.0.1 -p $PORT -s secretlab -t 8   (full log: $d/eapol_test.log)"
  set +e; timeout 30 eapol_test -c "$profile" -a 127.0.0.1 -p "$PORT" -s secretlab -t 8 > "$d/eapol_test.log" 2>&1; RC=$?; set -e
  kill "$hp" 2>/dev/null || true; wait "$hp" 2>/dev/null || true
  if kill -0 "$hp" 2>/dev/null; then echo "WARNING: hostapd pid $hp is still alive"; else echo "--- hostapd pid $hp stopped"; fi

  result=$(tail -n1 "$d/eapol_test.log")
  echo "Last eapol_test line: $result   (exit code $RC)"
  echo "--- Log lines that explain the reason (grep -E \"$pattern\"):"
  grep -E "$pattern" "$d/eapol_test.log" | head -n 4 || true
  reason=$(grep -m1 -E "$pattern" "$d/eapol_test.log" || true)
  if [ "$result" = "$expected" ] && [ -n "$reason" ]; then matched=YES; else matched=NO; FAILED=$((FAILED + 1)); fi
  TABLE+=("$(printf "$FMT" "$id" "$srv_label" "$profile_label" "$result" "$matched" "${reason:-(reason pattern not found)}")")
}

scenario S1 server-legit     wpa_supplicant.conf       SUCCESS "legit (real CA)"        "secure"             "TLS: Match in dNSName found"
scenario S2 server-rogue     wpa_supplicant.conf       FAILURE "rogue (twin CA)"        "secure"             "TLS: Certificate verification failed"
echo "Note S2: CA name, SAN and SKI are identical to the real ones; only the private key differs. The chain fails because the signature is wrong."
scenario S3 server-rogue     profile_weak.conf         SUCCESS "rogue (twin CA)"        "weak (no CA)"       "ca_cert_verify=0 depth=0"
scenario S4 server-wrongname profile_no_domain.conf    SUCCESS "wrong-name (real CA)"   "ca_cert, no domain" "ca_cert_verify=1 depth=0"
scenario S5 server-wrongname wpa_supplicant.conf       FAILURE "wrong-name (real CA)"   "secure"             "TLS: Domain match 'radius.rs-sehat.example' not found"

separator
echo "ANALYSIS S3 - weak profile accepted by the rogue server"
echo "Shown: without ca_cert, the supplicant still logs the signature failure (err=7) but ignores it,"
echo "  completes EAP-TLS with the attacker's server -> the device would join the attacker's network."
grep -m2 -E "ca_cert_verify=0 depth=0" evidence/S3/eapol_test.log || true
echo "NOT shown: theft of a password or private key. EAP-TLS sends no password,"
echo "  and the client private key never leaves the device (only the CertificateVerify signature)."
echo "Evidence from the rogue server side (hostapd S3), TLS handshake messages received from the client:"
grep -E 'OpenSSL: RX ver=.*content_type=22 \(handshake/' evidence/S3/hostapd.log | sed 's/.*(handshake\//  handshake\//' | sort | uniq -c
echo "RADIUS attributes in the rogue server log (request and reply); no User-Password:"
grep -oE 'Attribute [0-9]+ \([A-Za-z-]+\)' evidence/S3/hostapd.log | sort | uniq -c
echo "Occurrences of client key passphrase in rogue server log: $(grep -c 'lab-passphrase-synthetic' evidence/S3/hostapd.log || true)"
echo "What the attacker still gets: the client's PUBLIC identity/certificate and a position as access point (man-in-the-middle)."

separator
echo "ANALYSIS S4 - ca_cert alone is not enough"
echo "'TLS: Match domain' lines (name check) in S4: $(grep -c 'TLS: Match domain' evidence/S4/eapol_test.log || true)  (0 = no name check)"
grep -m1 -E "ca_cert_verify=1 depth=0" evidence/S4/eapol_test.log || true
echo "The 'printer' server has a valid certificate from the hospital CA, so it is accepted when the name is not checked."

separator
echo "TLS VERSION ACTUALLY NEGOTIATED (S1, from the eapol_test log)"
grep -E 'SSL: Using TLS version|Server selected cipher suite' evidence/S1/eapol_test.log | sort | uniq -c
grep -m1 -E 'OpenSSL: RX ver=0x[0-9a-f]+ content_type=22 \(handshake/server hello\)' evidence/S1/eapol_test.log || true
TLSVER=$(grep -oE 'SSL: Using TLS version TLSv[0-9.]+' evidence/S1/eapol_test.log | tail -n1 | awk '{print $NF}')
SUITE=$(grep -oE 'Server selected cipher suite 0x[0-9a-f]+' evidence/S1/eapol_test.log | awk '{print $NF}')
echo "TLS version in S1 : ${TLSVER:-unreadable}   (record version 0x303 = TLS 1.2)"
HEX=${SUITE#0x}
echo "Cipher suite      : $SUITE = $(openssl ciphers -V 'ALL:COMPLEMENTOFALL' | grep -i "0x${HEX:0:2},0x${HEX:2:2}" | head -n1 | sed 's/^ *//')"
echo "Note: TLS 1.3 is NOT negotiated and not forced; with wpa_supplicant/hostapd 2.10 the default configuration yields ${TLSVER:-?}."
if [ -n "$TLSVER" ]; then V_RC=0; else V_RC=1; fi
expect "TLS version read from the S1 log (${TLSVER:-empty})" 0 "$V_RC"

# ================================================================= FINAL TABLE
heading "FINAL TABLE"
printf "$FMT\n" "Scenario" "Server" "Profile" "Result" "As expected" "Reason (log)"
printf '%s\n' "----------+-----------------------+---------------------------+------------------+-------------------+-----------------------------"
for row in "${TABLE[@]}"; do printf '%s\n' "$row"; done
echo
echo "Expectation: S1 SUCCESS, S2 FAILURE, S3 SUCCESS, S4 SUCCESS, S5 FAILURE"
echo
echo "Supporting checks (steps 0-3):"
for row in "${CHECKS[@]}"; do printf '  %s\n' "$row"; done
echo
echo "Remaining hostapd processes: $(pgrep -c hostapd || true)"
if [ "$FAILED" -eq 0 ]; then echo "CONCLUSION: ALL expectations met (exit 0)."; exit 0
else echo "CONCLUSION: $FAILED expectation(s) NOT met (exit 1)."; exit 1; fi
