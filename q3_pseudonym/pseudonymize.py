#!/usr/bin/env python3
# pseudonymize.py - pseudonimisasi rekam medis (data sintetis) dengan HMAC-SHA256 (RFC 2104).
# Pemakaian: PSEUDO_KEY_HEX=<64 heks> python3 pseudonymize.py [K_MIN]
import csv
import hashlib
import hmac
import os
import re
import sys
from collections import defaultdict

REFERENCE_YEAR = 2026                  # usia dihitung terhadap tahun ini
DOMAIN_PREFIX = b"rs-sehat:pid:v1:"    # pemisahan domain: pesan HMAC khusus pid RS ini
QUASI_IDENTIFIERS = ("age_range", "sex", "postal_code_3")
COLUMNS = ("pid",) + QUASI_IDENTIFIERS + ("diagnosis_icd10", "visit_year")


def load_key():
    # Kunci hanya dibaca dari lingkungan; tidak pernah ada di kode maupun keluaran.
    try:
        key = bytes.fromhex(os.environ.get("PSEUDO_KEY_HEX", ""))
    except ValueError:
        key = b""
    if len(key) < 32:                  # RFC 2104: kunci minimal L byte, untuk SHA-256 L = 32
        print("Error: PSEUDO_KEY_HEX is missing, not hex, or shorter than 32 bytes.", file=sys.stderr)
        sys.exit(2)
    return key


def hmac_sha256(key, message):
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def pseudonym(nik, key):
    # fullmatch + ASCII menolak digit Unicode dan akhiran baris baru (jebakan "$" pada regex).
    if not re.fullmatch(r"\d{16}", nik, re.ASCII):
        raise ValueError("NIK must be exactly 16 digits")
    return hmac_sha256(key, DOMAIN_PREFIX + nik.encode())


def age_range(birth_date):             # birth_date berformat YYYY-MM-DD
    lower = (REFERENCE_YEAR - int(birth_date[:4])) // 10 * 10
    return f"{lower}-{lower + 9}"


def pseudonymize_rows(rows, key):
    # Pengenal langsung (name, nik, address, phone, birth_date) dibuang; hanya kolom turunan.
    return [{"pid": pseudonym(r["nik"], key), "age_range": age_range(r["birth_date"]),
             "sex": r["sex"], "postal_code_3": r["postal_code"][:3],
             "diagnosis_icd10": r["diagnosis_icd10"], "visit_year": r["visit_date"][:4]}
            for r in rows]


def class_of(row):
    return tuple(row[c] for c in QUASI_IDENTIFIERS)


def measure_k_l(rows):
    # k = jumlah pid BERBEDA per kelas (bukan baris, agar kunjungan ulang tak menggembungkan k).
    # l = jumlah diagnosis berbeda per kelas. Hasil: {kelas: (k, l)}.
    pids, dxs = defaultdict(set), defaultdict(set)
    for r in rows:
        pids[class_of(r)].add(r["pid"])
        dxs[class_of(r)].add(r["diagnosis_icd10"])
    return {c: (len(pids[c]), len(dxs[c])) for c in pids}


def suppress(rows, k_min):
    # Suppression: buang seluruh baris dari kelas yang k-nya kurang dari k_min.
    kl = measure_k_l(rows)
    return [r for r in rows if kl[class_of(r)][0] >= k_min]


def report(title, rows):
    kl = measure_k_l(rows).values()
    ks, ls = [v[0] for v in kl], [v[1] for v in kl]
    print(f"{title}: {len(rows)} rows, {len(ks)} classes, "
          f"k min={min(ks, default=0)} max={max(ks, default=0)}, "
          f"l min={min(ls, default=0)} max={max(ls, default=0)}")


def main():
    k_min = int(sys.argv[1]) if len(sys.argv) > 1 else 5
    key = load_key()                   # keluar dengan kode 2 bila kunci tidak layak
    with open("ehr_raw.csv", newline="", encoding="utf-8") as f:
        all_rows = pseudonymize_rows(list(csv.DictReader(f)), key)
    safe_rows = suppress(all_rows, k_min)
    with open("ehr_pseudonymized.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS, lineterminator="\n")
        w.writeheader()
        w.writerows(safe_rows)
    report("BEFORE suppression", all_rows)
    report(f"AFTER suppression (K_MIN={k_min})", safe_rows)
    print(f"rows kept={len(safe_rows)}, rows suppressed={len(all_rows) - len(safe_rows)}")
    print(f"{'class (age_range | sex | postal_3)':34} {'k':>2} {'l':>2}")
    for cls, (k, l) in sorted(measure_k_l(safe_rows).items()):
        dxs = sorted({r["diagnosis_icd10"] for r in safe_rows if class_of(r) == cls})
        flag = f"  <-- HOMOGENEITY RISK: all {dxs[0]}" if l == 1 else ""
        print(f"{' | '.join(cls):34} {k:2} {l:2}{flag}")


if __name__ == "__main__":
    main()
