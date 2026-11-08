#!/usr/bin/env python3
# generate_ehr.py - membangkitkan rekam kunjungan SINTETIS (tidak ada data pasien nyata).
# Seed tetap 2026, sehingga ehr_raw.csv identik pada setiap eksekusi.
import csv
import datetime
import random

rng = random.Random(2026)
REFERENCE_YEAR = 2026
# Kode provinsi 99 tidak diberikan kepada siapa pun, jadi NIK ini tidak mungkin milik orang nyata.
REGION_CODES = ["990101", "990102", "990201"]
# Kode pos sintetis (awalan 99 mengikuti konvensi NIK), tiga awalan 3 digit.
POSTAL_CODES = {"991": ["99101", "99102"], "992": ["99201", "99202", "99203"], "993": ["99301", "99302"]}
ICD_CODES = ["E11", "I10", "J18", "N18", "C50", "B20"]
COLUMNS = ["name", "nik", "address", "phone", "birth_date", "sex", "postal_code",
           "diagnosis_icd10", "visit_date"]

# Kelompok yang dirancang agar kelas hasil generalisasi (pita usia, sex, awalan pos) bermakna:
# (label, jumlah pasien, jumlah baris kunjungan, usia bawah, sex, awalan pos, diagnosis yang dipakai bergiliran)
GROUPS = [
    ("homogeneous", 6, 8, 30, "L", "991", ["B20"]),          # k=6 terpenuhi, tetapi semua B20 (l=1)
    ("large", 8, 10, 50, "P", "991", ["E11", "I10", "J18", "N18", "C50"]),  # k=8, l=5
    ("boundary", 5, 6, 60, "L", "992", ["E11", "I10"]),      # k=5 tepat di ambang K_MIN
    ("near_miss", 4, 4, 40, "P", "992", ["I10", "J18", "N18"]),  # k=4: tepat di bawah ambang
    ("repeat_visits", 3, 7, 20, "L", "993", ["J18"]),        # 7 baris tetapi hanya 3 pasien: k=3, bukan 7
]
SCATTERED = (19, 25)    # pasien tersebar acak (pasien, baris); sebagian besar kelasnya kecil

used_niks = set()


def random_birth_date(age_lower):
    # Usia (tahun acuan - tahun lahir) berada di pita age_lower..+9, dibatasi tahun lahir 1940-2010.
    low = max(age_lower, REFERENCE_YEAR - 2010)
    high = min(age_lower + 9, REFERENCE_YEAR - 1940)
    year = REFERENCE_YEAR - rng.randint(low, high)
    days_in_year = (datetime.date(year + 1, 1, 1) - datetime.date(year, 1, 1)).days
    return datetime.date(year, 1, 1) + datetime.timedelta(days=rng.randrange(days_in_year))


def make_nik(birth, sex):
    # 6 digit wilayah + DDMMYY lahir (perempuan: hari + 40) + 4 digit urut 0001-0020.
    while True:
        day = birth.day + (40 if sex == "P" else 0)
        nik = (f"{rng.choice(REGION_CODES)}{day:02d}{birth.month:02d}{birth.year % 100:02d}"
               f"{rng.randint(1, 20):04d}")
        if nik not in used_niks:
            used_niks.add(nik)
            return nik


def new_patient(age_lower, sex, postal_prefix, dx, n_visits):
    birth = random_birth_date(age_lower)
    return {"nik": make_nik(birth, sex), "birth_date": birth.isoformat(), "sex": sex,
            "postal_code": rng.choice(POSTAL_CODES[postal_prefix]), "dx": dx, "n": n_visits}


patients = []
designed_classes = set()
for _, n_patients, n_rows, age, sex, prefix, dxs in GROUPS:
    designed_classes.add((age, sex, prefix))
    for i in range(n_patients):
        n = n_rows // n_patients + (1 if i < n_rows % n_patients else 0)
        patients.append(new_patient(age, sex, prefix, dxs[i % len(dxs)], n))

# Pasien tersebar: tolak kelas yang sama dengan kelas rancangan atau yang sudah berisi 3 pasien.
fill = {}
scattered = []
while len(scattered) < SCATTERED[0]:
    cls = (rng.choice(range(10, 90, 10)), rng.choice("LP"), rng.choice(sorted(POSTAL_CODES)))
    if cls in designed_classes or fill.get(cls, 0) >= 3:
        continue
    fill[cls] = fill.get(cls, 0) + 1
    scattered.append(new_patient(cls[0], cls[1], cls[2], rng.choice(ICD_CODES), 1))
for idx in rng.sample(range(SCATTERED[0]), SCATTERED[1] - SCATTERED[0]):
    scattered[idx]["n"] = 2
patients += scattered

rng.shuffle(patients)
phones = rng.sample(range(1000, 10000), len(patients))
csv_rows = []
for no, p in enumerate(patients, 1):
    # Nilai nama, alamat, dan telepon adalah data sintetis, bukan kode.
    p.update(name=f"Pasien Sintetis {no:03d}", address=f"Jl. Sintetis No. {rng.randint(1, 99)}",
             phone=f"0800-0000-{phones[no - 1]}")
    for day in sorted(rng.sample(range(1095), p["n"])):     # kunjungan 2023-2025
        visit = datetime.date(2023, 1, 1) + datetime.timedelta(days=day)
        csv_rows.append({**p, "diagnosis_icd10": p["dx"], "visit_date": visit.isoformat()})
csv_rows.sort(key=lambda r: (r["visit_date"], r["name"]))

with open("ehr_raw.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=COLUMNS, extrasaction="ignore", lineterminator="\n")
    w.writeheader()
    w.writerows(csv_rows)

assert len(patients) == 45 and len(csv_rows) == 60 and all(len(p["nik"]) == 16 for p in patients)
print(f"ehr_raw.csv: {len(csv_rows)} visit rows from {len(patients)} synthetic patients")
