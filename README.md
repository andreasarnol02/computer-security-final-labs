# Ujian Akhir Computer Security: Lab Simulasi

Repositori ini berisi skrip untuk bagian **c. Simulasi** di setiap soal jawaban ujian akhir. Setiap lab:
- hanya memakai data sintetis;
- berjalan di satu kontainer Docker tanpa jaringan (`--network none`);
- dijalankan dengan satu perintah `bash run.sh`.

| Folder | Soal | Yang diuji | Skrip utama |
|---|---|---|---|
| `q1_iomt_audit/` | Soal 1 | Audit default credentials di perangkat IoMT tiruan | `audit_iomt.py` |
| `q2_wifi_eaptls/` | Soal 2 | Profil WPA3-Enterprise (EAP-TLS) melawan Evil Twin | `generate_profile.py`, `audit_profile.py` |
| `q3_pseudonym/` | Soal 3 | Pseudonimisasi data EHR dengan HMAC-SHA256 | `pseudonymize.py` |
| `q4_backup/` | Soal 4 | Backup terenkripsi di vault immutable melawan ransomware | `secure_backup.py` |
| `q5_idor/` | Soal 5 | IDOR di API SIMRS, sebelum dan sesudah perbaikan | `simrs_api.py` |

## Yang dibutuhkan

- **Docker.** Pakai Docker Desktop di Windows atau macOS, atau Docker Engine di Linux. Pastikan Docker sudah jalan: `docker info` harus berhasil.
- **bash.** Linux dan macOS sudah punya. Di Windows, jalankan dari WSL 2.
- **Internet hanya saat build image.** Lab-nya sendiri berjalan tanpa jaringan.
- **Ruang disk sekitar 500 MB** untuk image.

## Langkah demi langkah

### 1. Ambil repositori

```bash
git clone https://github.com/andreasarnol02/computer-security-final-labs.git
cd computer-security-final-labs
```

### 2. Build image (cukup sekali)

```bash
docker build -t final-lab:1 .
```

Image ini berisi Python 3.12 dan alat yang dipakai lab:

| Alat | Dipakai oleh |
|---|---|
| nmap | Soal 1 |
| wpa_supplicant, eapol_test, hostapd | Soal 2 |
| openssl | Soal 2, 3, 4, 5 |
| e2fsprogs (`chattr`) | Soal 4 |
| library `cryptography` | Soal 4 |

Build-nya memakan beberapa menit.

### 3. Jalankan lab

Jalankan satu lab, misalnya Soal 1:

```bash
bash q1_iomt_audit/run.sh
```

Perintah yang sama berlaku untuk folder lain. `run.sh` bisa dipanggil dari folder mana pun karena ia pindah ke foldernya sendiri. Setiap `run.sh` melakukan tiga hal:
1. menyalakan kontainernya sendiri;
2. membuat data sintetis, key, dan sertifikat yang dibutuhkan;
3. menjalankan semua pengujian, mencetaknya ke terminal, dan menyimpan keluaran yang sama ke `run_output.txt`.

### 4. Baca hasilnya

Setiap lab diakhiri satu baris kesimpulan. Kalau baris itu muncul, semua pengujian sesuai ekspektasi:

| Lab | Baris terakhir yang diharapkan |
|---|---|
| Soal 1 | `SCENARIO DONE: all checks as expected.` |
| Soal 2 | `CONCLUSION: ALL expectations met (exit 0).` |
| Soal 3 | `Summary: 9/9 PASS`, lalu `[PASS] HMAC key not found ...` |
| Soal 4 | `FINAL STATUS: all rows as expected` |
| Soal 5 | `exit run.sh=0` |

Key dan PKI dibuat ulang secara acak di setiap run. Karena itu, sebagian isi `run_output.txt` bisa berbeda, misalnya hash dan fingerprint, tetapi baris kesimpulannya harus sama.

## Isi setiap lab

### Soal 1: `q1_iomt_audit/`

`iomt_lab.py` menyalakan empat perangkat IoMT tiruan di 127.0.10.11 sampai .14, semuanya di dalam kontainer. Lalu `scenario.sh` menjalankan empat tahap:
- **A.** Audit awal dengan `audit_iomt.py`, yang menguji tiga default credentials di Telnet dan HTTP.
- **B.** `nmap` dipakai sebagai pemeriksa independen, lalu hasilnya dibandingkan dengan laporan audit.
- **C.** Pompa .11 diremediasi (`--hardened`), lalu audit dan `nmap` dijalankan ulang.
- **D.** Kontrol negatif untuk pagar lingkup: tanpa `--authorized`, jaringan publik, dan prefix terlalu lebar harus ditolak dengan exit code 2, tanpa membuka socket.

Unit test-nya dijalankan terpisah:

```bash
cd q1_iomt_audit
docker run --rm --network none -v "$PWD:/lab" -w /lab final-lab:1 python -m unittest -v test_audit
```

### Soal 2: `q2_wifi_eaptls/`

- **STEP 0.** `make_pki.sh` membuat PKI sintetis: Root CA rumah sakit, CA palsu, serta sertifikat server dan klien. `generate_profile.py` lalu membuat profil aman `wpa_supplicant.conf`.
- **STEP 1.** `openssl verify` memeriksa sertifikat terhadap CA rumah sakit.
- **STEP 2.** `audit_profile.py` membandingkan profil aman dengan dua profil lemah.
- **STEP 3.** Parser `wpa_supplicant` membaca profilnya, termasuk satu profil dengan salah ketik.
- **STEP 4.** Handshake EAP-TLS nyata antara `eapol_test` dan `hostapd` untuk skenario S1 sampai S5, termasuk server palsu.

### Soal 3: `q3_pseudonym/`

1. `generate_ehr.py` membuat data EHR sintetis dengan seed tetap 2026.
2. `pseudonymize.py` membuang pengenal langsung dan mengganti NIK dengan HMAC-SHA256.
3. Ukuran k dan l dihitung.
4. `verify_output.py` menjalankan uji T1 sampai T9.

Key HMAC dibuat acak di dalam kontainer. Key itu tidak pernah ditulis ke berkas, dan langkah terakhir memeriksa bahwa key tidak muncul di berkas mana pun.

### Soal 4: `q4_backup/`

Lab ini **wajib** memakai `--privileged`, karena membuat vault ext4 64 MB lewat loop mount dan memasang flag immutable (`chattr +i`). Semuanya terjadi di dalam kontainer, dan vault dilepas lagi di akhir.

| Tahap | Yang diuji |
|---|---|
| A | Enkripsi AES-256-GCM dengan `openssl enc` dan known-answer test (`test_gcm_kat.py`) |
| B | Backup ke vault, lalu restore. sha256 setiap berkas harus sama dengan aslinya. |
| C | Arsip yang diubah satu byte, key yang salah, dan key yang melanggar aturan harus ditolak. |
| D | Percobaan menimpa arsip oleh user lain, pemilik, dan root, dengan dan tanpa flag immutable |
| E | Simulasi ransomware menimpa data produksi, lalu restore dari vault |

### Soal 5: `q5_idor/`

`simrs_api.py` menjalankan tiga versi endpoint resep:
- `/v1`: rentan IDOR;
- `/rbac-only`: hanya memeriksa peran;
- `/v2`: memeriksa peran dan relasi dokter-pasien.

`test_primitives.py` mencocokkan tanda tangan token HS256 dengan vektor uji RFC 7515 dan dengan `openssl`. `test_attacks.py` menjalankan skenario serangan. Ada juga pemeriksa independen dengan klien HTTP terpisah:

```bash
bash q5_idor/test_http_independent.sh
```

## Kalau memakai Docker context lain

Secara bawaan, skrip memakai Docker context yang aktif. Kalau Docker berjalan di context lain, misalnya Colima, tentukan lewat variabel lingkungan:

```bash
LAB_DOCKER_CONTEXT=colima bash q1_iomt_audit/run.sh
```
