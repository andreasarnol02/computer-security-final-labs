#!/usr/bin/env bash
# Membuat PKI sintetis untuk simulasi EAP-TLS (hanya OpenSSL, keluaran di pki/).
# Semua nama, domain, dan passphrase adalah nilai laboratorium, bukan data nyata.
set -euo pipefail
cd "$(dirname "$0")"

PKI_DIR=pki
PASS='lab-passphrase-synthetic'
SUBJ_CA='/C=ID/O=RS Sehat (synthetic)/CN=RS Sehat Root CA'   # dipakai oleh CA asli DAN CA palsu
DAYS_CA=3650
DAYS_LEAF=825

rm -rf "$PKI_DIR"
mkdir -p "$PKI_DIR"
chmod 700 "$PKI_DIR"
umask 077            # semua berkas kunci otomatis 0600
cd "$PKI_DIR"

# --- Pembantu -------------------------------------------------------------
# new_ca <name> [<hex-SKI>] : CA root self-signed; SKI bisa ditiru (nilai publik).
new_ca() {
  local name=$1 ski=${2:-hash}
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$name.key" 2>/dev/null
  cat > "$name.cnf" <<EOF
[req]
distinguished_name = dn
[dn]
[v3_ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = $ski
EOF
  openssl req -new -x509 -key "$name.key" -subj "$SUBJ_CA" -days $DAYS_CA \
    -sha256 -config "$name.cnf" -extensions v3_ca -out "$name.pem"
}

# new_leaf <name> <CA> <subject> <extra-ext...> : sertifikat ujung ditandatangani CA.
new_leaf() {
  local name=$1 ca=$2 subj=$3; shift 3
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$name.key" 2>/dev/null
  openssl req -new -key "$name.key" -subj "$subj" -out "$name.csr"
  {
    echo "basicConstraints = critical, CA:FALSE"
    echo "keyUsage = critical, digitalSignature, keyEncipherment"
    echo "subjectKeyIdentifier = hash"
    echo "authorityKeyIdentifier = keyid"
    printf '%s\n' "$@"
  } > "$name.ext"
  openssl x509 -req -in "$name.csr" -CA "$ca.pem" -CAkey "$ca.key" -CAcreateserial \
    -days $DAYS_LEAF -sha256 -extfile "$name.ext" -out "$name.pem" 2>/dev/null
  rm -f "$name.csr"
}

# --- 1. CA root rumah sakit (asli) ------------------------------------------
new_ca rs-root-ca

# --- 2. Server RADIUS sah: SAN radius.rs-sehat.example -----------------------
new_leaf server-legit rs-root-ca '/C=ID/O=RS Sehat (synthetic)/CN=radius.rs-sehat.example' \
  'subjectAltName = DNS:radius.rs-sehat.example' 'extendedKeyUsage = serverAuth'

# --- 3. Sertifikat klien nurse01 + kunci privat TERENKRIPSI ----------------
new_leaf client-nurse01 rs-root-ca '/C=ID/O=RS Sehat (synthetic)/CN=nurse01@rs-sehat.example' \
  'subjectAltName = email:nurse01@rs-sehat.example' 'extendedKeyUsage = clientAuth'
openssl pkcs8 -topk8 -v2 aes-256-cbc -in client-nurse01.key -out client-nurse01.enc.key \
  -passout "pass:$PASS"
mv client-nurse01.enc.key client-nurse01.key      # kunci polos diganti versi terenkripsi
chmod 600 client-nurse01.key

# --- 4. CA PALSU: subjek IDENTIK, kunci berbeda; SKI publik ikut ditiru ------
HOSPITAL_SKI=$(openssl x509 -in rs-root-ca.pem -noout -ext subjectKeyIdentifier | tail -n1 | tr -d ' ')
new_ca rogue-ca "$HOSPITAL_SKI"
new_leaf server-rogue rogue-ca '/C=ID/O=RS Sehat (synthetic)/CN=radius.rs-sehat.example' \
  'subjectAltName = DNS:radius.rs-sehat.example' 'extendedKeyUsage = serverAuth'

# --- 5. "Nama salah": ditandatangani CA ASLI, tetapi SAN printer ------------
new_leaf server-wrongname rs-root-ca '/C=ID/O=RS Sehat (synthetic)/CN=printer.rs-sehat.example' \
  'subjectAltName = DNS:printer.rs-sehat.example' 'extendedKeyUsage = serverAuth'

rm -f ./*.ext ./*.cnf ./*.srl
chmod 600 ./*.key
chmod 644 ./*.pem
echo "Synthetic PKI created in $(pwd):"
ls -l
