#!/usr/bin/env python3
# Audit profil wpa_supplicant terhadap 8 aturan keamanan (R1-R8). Exit 1 bila ada FAIL.
import os, re, subprocess, sys

def parse_network_blocks(path):
    """Ambil tiap blok network={...} sebagai dict kunci -> nilai (tanda kutip dibuang)."""
    text, blocks = open(path).read(), []
    for body in re.findall(r"network\s*=\s*\{(.*?)^\s*\}", text, re.S | re.M):
        block = {}
        for line in body.splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                block[key.strip()] = value.strip().strip('"')
        blocks.append(block)
    return blocks

def run_openssl(*args):
    """Jalankan openssl, kembalikan (kode_keluar, keluaran)."""
    proc = subprocess.run(["openssl", *args], capture_output=True, text=True)
    return proc.returncode, proc.stdout + proc.stderr

def file_mode(path):
    """Mode berkas dalam oktal, atau None bila berkas tidak ada."""
    return f"{os.stat(path).st_mode & 0o777:04o}" if os.path.isfile(path) else None

def check_eap_tls(block, conf):  # R1: hanya EAP-TLS (sertifikat dua arah, RFC 5216)
    return block.get("eap") == "TLS", f"eap={block.get('eap')}"

def check_akm(block, conf):  # R2: AKM harus berbasis SHA-256/Suite-B dan tidak boleh ada PSK atau NONE
    key_mgmt = block.get("key_mgmt", "").split()
    good = any(k in ("WPA-EAP-SHA256", "WPA-EAP-SUITE-B-192") for k in key_mgmt)
    bad = any(k.startswith("WPA-PSK") or k == "NONE" for k in key_mgmt)
    return good and not bad, f"key_mgmt={' '.join(key_mgmt)}"

def check_pmf(block, conf):  # R3: PMF wajib (IEEE 802.11w, ieee80211w=2)
    return block.get("ieee80211w") == "2", f"ieee80211w={block.get('ieee80211w')}"

def check_ca_cert(block, conf):  # R4: ca_cert ada, berkas ada, X.509 valid, CA:TRUE, belum kedaluwarsa
    ca = block.get("ca_cert", "")
    if not ca or not os.path.isfile(ca): return False, f"ca_cert missing or file not found ({ca or '-'})"
    rc, out = run_openssl("x509", "-in", ca, "-noout", "-ext", "basicConstraints")
    if rc: return False, "not a valid X.509 certificate"
    if "CA:TRUE" not in out: return False, "not a CA (CA:TRUE absent)"
    if run_openssl("x509", "-in", ca, "-noout", "-checkend", "0")[0]: return False, "expired"
    return True, "valid X.509, CA:TRUE, not expired"

def check_domain_match(block, conf):  # R5: nama server wajib dicocokkan, kalau tidak server lain dari CA yang sama lolos
    value = block.get("domain_match") or block.get("domain_suffix_match")
    return bool(value), f"domain_match/domain_suffix_match={value or '(empty)'}"

def check_client_chain(block, conf):  # R6: sertifikat klien harus berantai ke ca_cert
    ca, client_cert = block.get("ca_cert", ""), block.get("client_cert", "")
    if not (os.path.isfile(ca) and os.path.isfile(client_cert)): return False, "ca_cert/client_cert not found"
    rc, out = run_openssl("verify", "-CAfile", ca, client_cert)
    return rc == 0, (out.strip().splitlines() or ["?"])[-1]

def check_tls_versions(block, conf):  # R7: TLS 1.0/1.1 dimatikan dan pemeriksaan waktu sertifikat tidak dimatikan
    opts = dict(x.split("=", 1) for x in block.get("phase1", "").split() if "=" in x)
    ok = opts.get("tls_disable_time_checks") != "1" and opts.get("tls_disable_tlsv1_0") == "1" and opts.get("tls_disable_tlsv1_1") == "1"
    return ok, f"phase1={block.get('phase1', '(empty)')}"

def check_file_modes(block, conf):  # R8: berkas konfigurasi dan kunci privat tidak boleh terbaca group/world
    modes = [file_mode(conf), file_mode(block.get("private_key", ""))]
    return all(m and int(m, 8) & 0o077 == 0 for m in modes), f"mode conf={modes[0]} private_key={modes[1]}"

RULES = [("R1", "EAP-TLS only", check_eap_tls), ("R2", "AKM SHA-256/Suite-B, not PSK", check_akm),
         ("R3", "PMF required", check_pmf), ("R4", "ca_cert valid and a CA", check_ca_cert),
         ("R5", "domain_match set", check_domain_match), ("R6", "client certificate chains to CA", check_client_chain),
         ("R7", "TLS 1.0/1.1 off, time checks on", check_tls_versions), ("R8", "strict file permissions", check_file_modes)]

conf, failed = sys.argv[1], []
if not os.path.isfile(conf): sys.exit(f"File not found: {conf}")
blocks = parse_network_blocks(conf)
print(f"Audit {conf}: {len(blocks)} network block(s)")
for i, block in enumerate(blocks, 1):
    print(f"-- network #{i} ssid={block.get('ssid', '?')}")
    for code, title, check in RULES:
        ok, detail = check(block, conf)
        print(f"  {'PASS' if ok else 'FAIL'} {code} {title}: {detail}")
        if not ok: failed.append(code)
if not blocks: failed.append("no network block")
print("RESULT:", "ALL PASS" if not failed else "FAIL -> " + " ".join(failed))
sys.exit(1 if failed else 0)
