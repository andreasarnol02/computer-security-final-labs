#!/usr/bin/env python3
# Pembuat profil Wi-Fi Enterprise aman untuk wpa_supplicant (EAP-TLS, PMF wajib).
# Semua nama dan kata sandi di bawah ini adalah nilai sintetis laboratorium.
import os

PKI_DIR = os.path.abspath("pki")  # folder sertifikat hasil make_pki.sh
OUTPUT_FILE = "wpa_supplicant.conf"

global_conf = [
    "ctrl_interface=/run/wpa_supplicant",  # soket kendali daemon
    "update_config=0",                     # daemon tidak boleh menulis ulang profil
    "pmf=2",                               # Protected Management Frames wajib (IEEE 802.11w)
]

network_block = [
    'ssid="RS-Sehat-Enterprise"',
    "scan_ssid=1",                         # cari SSID tersembunyi secara aktif
    "proto=RSN",                           # hanya WPA2/WPA3 (RSN), bukan WPA1
    "key_mgmt=WPA-EAP-SHA256",             # 802.1X dengan AKM berbasis SHA-256
    "ieee80211w=2",                        # PMF wajib untuk jaringan ini
    "pairwise=CCMP",                       # enkripsi unicast AES-CCMP
    "group=CCMP",                          # enkripsi broadcast AES-CCMP
    "eap=TLS",                             # sertifikat dua arah, tanpa kata sandi
    'identity="nurse01@rs-sehat.example"',
    f'ca_cert="{PKI_DIR}/rs-root-ca.pem"',  # jangkar kepercayaan: hanya CA rumah sakit
    'domain_match="radius.rs-sehat.example"',  # nama server harus cocok dengan SAN
    f'client_cert="{PKI_DIR}/client-nurse01.pem"',
    f'private_key="{PKI_DIR}/client-nurse01.key"',  # kunci terenkripsi, mode 0600
    'private_key_passwd="lab-passphrase-synthetic"',
    'phase1="tls_disable_tlsv1_0=1 tls_disable_tlsv1_1=1"',  # tolak TLS 1.0 dan 1.1
]

content = "\n".join(global_conf) + "\n\nnetwork={\n" + "".join(f"    {line}\n" for line in network_block) + "}\n"
fd = os.open(OUTPUT_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)  # dibuat 0600 sejak awal
with os.fdopen(fd, "w") as f:
    f.write(content)
os.chmod(OUTPUT_FILE, 0o600)  # pastikan 0600 walaupun berkas lama sudah ada
print(f"Secure profile written to {OUTPUT_FILE} (mode 0600)")
