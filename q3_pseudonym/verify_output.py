#!/usr/bin/env python3
# verify_output.py - uji T1..T9 untuk pseudonimisasi HMAC-SHA256. Semua angka diukur saat dijalankan.
# Kunci asli dibaca dari PSEUDO_KEY_HEX (lewat load_key) dan tidak pernah dicetak.
import contextlib
import csv
import datetime
import hashlib
import hmac
import io
import os
import subprocess
import sys
import time
from collections import Counter, defaultdict

from pseudonymize import DOMAIN_PREFIX, hmac_sha256, load_key, measure_k_l, pseudonym, pseudonymize_rows, suppress

sys.stdout.reconfigure(line_buffering=True)
DIRECT_IDENTIFIERS = ("name", "nik", "address", "phone", "birth_date")
REGION_CODES = ("990101", "990102", "990201")
ALL_SERIALS = [f"{s:04d}" for s in range(1, 10000)]


def read_rows(path):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


key = load_key()
raw = read_rows("ehr_raw.csv")
niks = sorted({r["nik"] for r in raw})
all_rows = pseudonymize_rows(raw, key)           # seluruh baris, sebelum penekanan
wrong_key = hashlib.sha256(b"attacker guessed key").digest()    # kunci tebakan penyerang yang salah


def t1():
    # Known-answer test: vektor uji resmi RFC 4231 harus cocok persis.
    vectors = [("TC1", bytes([0x0B]) * 20, b"Hi There",
                "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
               ("TC2", b"Jefe", b"what do ya want for nothing?",
                "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")]
    ok = True
    for name, k, data, expected in vectors:
        result = hmac_sha256(k, data)
        print(f"    RFC 4231 {name}\n      result   {result}\n      expected {expected}")
        ok &= result == expected
    return ok


def t2():
    # Oracle independen: openssl menghitung HMAC yang sama tanpa memakai kode Python di atas.
    nik = niks[0]
    message = DOMAIN_PREFIX + nik.encode()
    p = subprocess.run(["openssl", "dgst", "-sha256", "-mac", "HMAC", "-macopt", "hexkey:" + key.hex()],
                       input=message, capture_output=True)
    if p.returncode != 0:                        # argumen tidak dicetak karena memuat kunci
        print(f"    openssl failed, exit code {p.returncode}")
        return False
    oracle = p.stdout.decode().strip().split("= ")[-1]
    own = pseudonym(nik, key)
    print(f"    message {message!r}\n    openssl {oracle}\n    python  {own}")
    return oracle == own


def t3():
    # Pseudonim harus deterministik agar kunjungan ulang satu pasien tetap terhubung.
    mapping = defaultdict(set)
    for r, s in zip(raw, all_rows):
        mapping[r["nik"]].add(s["pid"])
    repeat_nik = sum(1 for v in Counter(r["nik"] for r in raw).values() if v > 1)
    repeat_pid = sum(1 for v in Counter(s["pid"] for s in all_rows).values() if v > 1)
    same = all(len(v) == 1 for v in mapping.values()) and pseudonym(niks[0], key) == pseudonym(niks[0], key)
    invalid = ["", "123", "12345678901234567", "1234567890123456\n", "１" * 16]    # termasuk jebakan "$" dan digit Unicode
    rejected = 0
    for nik in invalid:
        try:
            pseudonym(nik, key)
        except ValueError:
            rejected += 1
    print(f"    patients with >1 row: raw={repeat_nik}, pseudonymized={repeat_pid}")
    print(f"    distinct NIK={len(niks)}, distinct pid={len({s['pid'] for s in all_rows})}, "
          f"each NIK -> exactly one pid: {same}")
    print(f"    invalid NIK rejected: {rejected}/{len(invalid)}")
    return repeat_nik == repeat_pid and repeat_nik > 0 and same \
        and len(mapping) == len({s["pid"] for s in all_rows}) and rejected == len(invalid)


def t4():
    # Kunci berbeda harus menghasilkan pid yang tidak beririsan, jadi pid tidak bisa ditautkan antarkunci.
    key_b = os.urandom(32)
    pids_a = {pseudonym(n, key) for n in niks}
    pids_b = {pseudonym(n, key_b) for n in niks}
    print(f"    pids key A={len(pids_a)}, pids key B={len(pids_b)}, overlap={len(pids_a & pids_b)}")
    return len(pids_a & pids_b) == 0 and len(pids_a) == len(niks)


def t5():
    # Pemindaian kebocoran: tidak ada nilai pengenal langsung yang boleh muncul di keluaran.
    with open("ehr_pseudonymized.csv", encoding="utf-8") as f:
        output = f.read()
    with open("ehr_raw.csv", encoding="utf-8") as f:
        source = f.read()
    values = sorted({r[c] for r in raw for c in DIRECT_IDENTIFIERS})
    leaked = [v for v in values if v in output]
    control = [v for v in values if v in source]       # kontrol positif: pemindai harus menemukan semuanya di data mentah
    header = output.splitlines()[0]
    print(f"    output columns: {header}")
    print(f"    direct identifier values scanned: {len(values)}; found in output: {len(leaked)}")
    print(f"    positive control (scan ehr_raw.csv): found {len(control)}/{len(values)}")
    return not leaked and len(control) == len(values) and len(output.splitlines()) > 1


def t6():
    # Penyerang tahu kode wilayah dan tanggal lahir; sisanya hanya nomor urut 0001-9999.
    nik = niks[0]
    known_prefix = nik[:12]                              # kode wilayah + tanggal lahir diketahui penyerang
    candidates = [known_prefix + s for s in ALL_SERIALS]    # serial 0001-9999
    plain_target = hashlib.sha256(nik.encode()).hexdigest()
    hmac_target = pseudonym(nik, key)

    t0 = time.perf_counter()
    plain_hits = [c for c in candidates if hashlib.sha256(c.encode()).hexdigest() == plain_target]
    plain_ms = (time.perf_counter() - t0) * 1000
    t0 = time.perf_counter()
    wrong_hits = [c for c in candidates if hmac_sha256(wrong_key, DOMAIN_PREFIX + c.encode()) == hmac_target]
    hmac_ms = (time.perf_counter() - t0) * 1000
    right_hits = [c for c in candidates if pseudonym(c, key) == hmac_target]       # kontrol: kunci benar memang cocok

    print(f"    plain SHA-256  : {len(candidates)} candidates tried, recovered={len(plain_hits)} "
          f"(NIK {plain_hits[0] if plain_hits else '-'} at position "
          f"{candidates.index(plain_hits[0]) + 1 if plain_hits else '-'}), {plain_ms:.1f} ms")
    print(f"    HMAC wrong key : {len(candidates)} candidates tried, recovered={len(wrong_hits)}, {hmac_ms:.1f} ms")
    print(f"    control (HMAC with correct key): recovered={len(right_hits)}")
    return plain_hits == [nik] and not wrong_hits and right_hits == [nik]


def t7():
    # Serangan seluruh dataset: enumerasi wilayah x tanggal lahir x sex x nomor urut.
    dates = [datetime.date(1940, 1, 1) + datetime.timedelta(days=i)
             for i in range((datetime.date(2010, 12, 31) - datetime.date(1940, 1, 1)).days + 1)]
    prefixes = [f"{w}{d.day + add:02d}{d.month:02d}{d.year % 100:02d}".encode()
                for w in REGION_CODES for d in dates for add in (0, 40)]       # wilayah x tanggal x sex
    serials = [s.encode() for s in ALL_SERIALS[:20]]                              # urut 0001-0020
    total = len(prefixes) * len(serials)
    plain_column = {hashlib.sha256(n.encode()).digest() for n in niks}
    hmac_column = {bytes.fromhex(pseudonym(n, key)) for n in niks}

    t0 = time.perf_counter()
    plain_recovered = {h for a in prefixes for s in serials if (h := hashlib.sha256(a + s).digest()) in plain_column}
    plain_secs = time.perf_counter() - t0
    t0 = time.perf_counter()
    hmac_recovered = {h for a in prefixes for s in serials
                      if (h := hmac.digest(wrong_key, DOMAIN_PREFIX + a + s, "sha256")) in hmac_column}
    hmac_secs = time.perf_counter() - t0

    n = len(niks)
    print(f"    candidates: 3 regions x {len(dates)} dates x 2 sexes x {len(serials)} serials = {total}")
    print(f"    plain SHA-256  : recovered {len(plain_recovered)}/{n} = {100 * len(plain_recovered) / n:.1f}% in {plain_secs:.2f} seconds")
    print(f"    HMAC wrong key : recovered {len(hmac_recovered)}/{n} = {100 * len(hmac_recovered) / n:.1f}% in {hmac_secs:.2f} seconds")
    return total == len(prefixes) * 20 and len(plain_recovered) == n and len(hmac_recovered) == 0


def t8():
    # Kunci hilang atau terlalu pendek harus menghentikan program (exit 2) tanpa keluaran data.
    ok = True
    for label, test_key in (("key missing", None), ("16-byte key", os.urandom(16).hex())):
        env = {k: v for k, v in os.environ.items() if k != "PSEUDO_KEY_HEX"}
        if test_key:
            env["PSEUDO_KEY_HEX"] = test_key
        p = subprocess.run([sys.executable, "pseudonymize.py"], env=env, capture_output=True, text=True)
        print(f"    {label}: exit code={p.returncode}, message: {p.stderr.strip()}")
        ok &= p.returncode == 2 and p.stdout == ""
    for n_bytes, expected in ((31, 2), (32, 0)):       # batas bawah: 31 byte ditolak, 32 byte diterima
        os.environ["PSEUDO_KEY_HEX"] = os.urandom(n_bytes).hex()
        try:
            with contextlib.redirect_stderr(io.StringIO()):
                load_key()
            code = 0
        except SystemExit as e:
            code = e.code
        finally:
            os.environ["PSEUDO_KEY_HEX"] = key.hex()
        print(f"    boundary: {n_bytes}-byte key -> code {code} (expected {expected})")
        ok &= code == expected
    return ok


def t9():
    # k harus menghitung pid berbeda; menghitung baris akan menggembungkan k oleh kunjungan ulang.
    one = {"pid": "p1", "age_range": "30-39", "sex": "L", "postal_code_3": "991", "diagnosis_icd10": "I10"}
    five_visits = [dict(one) for _ in range(5)]                          # 1 pasien, 5 kunjungan
    five_patients = [dict(one, pid=f"p{i}") for i in range(5)]           # 5 pasien, 1 kunjungan
    k1 = next(iter(measure_k_l(five_visits).values()))[0]
    k5 = next(iter(measure_k_l(five_patients).values()))[0]
    print(f"    1 patient x 5 visits: k={k1} (counting rows would wrongly give 5); "
          f"5 patients x 1 visit: k={k5}")
    print(f"    suppression K_MIN=5: 1 patient x 5 visits -> {len(suppress(five_visits, 5))} rows left; "
          f"5 patients -> {len(suppress(five_patients, 5))} rows left")
    rows_per_class = Counter((s["age_range"], s["sex"], s["postal_code_3"]) for s in all_rows)
    for cls, (k, _) in sorted(measure_k_l(all_rows).items()):
        if rows_per_class[cls] >= 5 and k < 5:
            print(f"    real data: class {' | '.join(cls)} has {rows_per_class[cls]} rows but only k={k} patients -> suppressed")
    return k1 == 1 and k5 == 5 and not suppress(five_visits, 5) and len(suppress(five_patients, 5)) == 5


def run_test(code, title, func):
    print(f"\n--- {code}: {title}")
    try:
        ok = bool(func())
    except Exception as e:                          # hanya nama galat: pesan bisa memuat argumen berisi kunci
        print(f"    unexpected error: {type(e).__name__}")
        ok = False
    print(f"[{'PASS' if ok else 'FAIL'}] {code} {title}")
    return ok


TESTS = [("T1", "RFC 4231 known-answer HMAC-SHA-256 (TC1, TC2)", t1),
         ("T2", "independent oracle openssl dgst -mac HMAC", t2),
         ("T3", "determinism and linkage of repeat patients", t3),
         ("T4", "two different keys -> disjoint pids", t4),
         ("T5", "direct identifier leak scan", t5),
         ("T6", "basic attack: region + birth date known, serial enumeration", t6),
         ("T7", "whole-dataset attack: enumerate region x date x sex x serial", t7),
         ("T8", "missing or 16-byte key -> exit code 2", t8),
         ("T9", "k counts distinct pids, not rows", t9)]

if __name__ == "__main__":
    results = [run_test(*t) for t in TESTS]
    print(f"\nSummary: {sum(results)}/{len(results)} PASS")
    sys.exit(0 if all(results) else 1)
