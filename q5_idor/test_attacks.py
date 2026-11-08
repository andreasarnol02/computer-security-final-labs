#!/usr/bin/env python3
"""Uji serangan IDOR atas simrs_api.py lewat HTTP sungguhan di 127.0.0.1:18080.

Status diambil dari respons HTTP; perubahan data diambil langsung dari penyimpanan
server, sehingga server tidak bisa "mengaku" menolak sambil tetap menulis.
Data di-reset sebelum setiap permintaan; AUDIT sengaja tidak di-reset.
"""
import base64, collections, copy, http.client, json, os, subprocess, sys, threading, time

import simrs_api as api

HOST, PORT = "127.0.0.1", 18080
V1, RBAC, V2 = "/v1/prescriptions/", "/rbac-only/prescriptions/", "/v2/prescriptions/"
EDIT = {"dose": "1000 mg 4x1"}
AUDIT_FIELDS = {"time", "sub", "role", "action", "object", "decision", "reason"}

MAIN_ROWS, EXTRA_ROWS, RESULTS = [], [], {}


def b64u(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def json_b64u(obj):
    return b64u(json.dumps(obj, separators=(",", ":")).encode())


def b64u_decode(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def valid_token(sub, role):
    return api.make_token(sub, role, 300)


def tampered_signature(token):
    # Bit pada byte pertama dibalik; karakter terakhir base64url punya bit tak terpakai.
    h, p, s = token.split(".")
    raw = bytearray(b64u_decode(s))
    raw[0] ^= 1
    return f"{h}.{p}.{b64u(bytes(raw))}"


def changed_role(token, role):
    h, p, s = token.split(".")
    return f"{h}.{json_b64u({**json.loads(b64u_decode(p)), 'role': role})}.{s}"


def alg_none_token(sub, role, valid_signature=False):
    h = json_b64u({"alg": "none", "typ": "JWT"})
    p = json_b64u({"sub": sub, "role": role, "iss": api.ISS, "aud": api.AUD,
                   "exp": int(time.time()) + 300})
    s = api.sign(f"{h}.{p}".encode(), api.jwt_key()) if valid_signature else ""
    return f"{h}.{p}.{s}"


def send_http(method, path, token, body, headers):
    request_headers = dict(headers or {})
    if token is not None:
        request_headers["Authorization"] = f"Bearer {token}"
    data = body if isinstance(body, bytes) or body is None else json.dumps(body).encode()
    if data is not None:
        request_headers["Content-Type"] = "application/json"
    connection = http.client.HTTPConnection(HOST, PORT, timeout=5)
    try:
        connection.request(method, path, body=data, headers=request_headers)
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def run_case(rows, no, scenario, method, prefix, rid, token, body, expected_status,
             expected_changed, reason=None, check=None, headers=None):
    """Satu permintaan terhadap data yang baru di-reset; hasilnya satu baris tabel."""
    api.reset_data()
    before = copy.deepcopy(api.PRESCRIPTIONS)
    audit_count = len(api.AUDIT)
    status, content = send_http(method, prefix + rid, token, body, headers)
    after = copy.deepcopy(api.PRESCRIPTIONS)
    new_audit = [json.loads(x) for x in api.AUDIT[audit_count:]]
    changed = before != after

    problems = []
    if status != expected_status:
        problems.append(f"expected status {expected_status}")
    if changed != expected_changed:
        problems.append("expected data " + ("changed" if expected_changed else "unchanged"))
    if expected_changed and changed:
        # Perubahan harus tepat isi body, bukan sekadar "ada yang berbeda".
        expected_data = copy.deepcopy(before)
        expected_data[rid].update(body)
        if after != expected_data:
            problems.append("wrong change content")
    if method == "GET" and status == 200 and json.loads(content) != before.get(rid):
        problems.append("wrong read content")
    if prefix == V2:
        decision = "allow" if status == 200 else "deny"
        if len(new_audit) != 1 or new_audit[0].get("decision") != decision:
            problems.append(f"expected one {decision} audit record")
        elif reason and new_audit[0].get("reason") != reason:
            problems.append(f"expected audit reason {reason}, got {new_audit[0].get('reason')}")
    elif new_audit:
        problems.append("legacy endpoint must not audit")
    if check and not check(content):
        problems.append("body check failed")

    RESULTS[no] = {"status": status, "content": content, "before": before, "after": after,
                   "audit": new_audit}
    rows.append((no, scenario, f"{method} {prefix}{rid}", str(status),
                 "YES" if changed else "NO",
                 "YES" if not problems else "NO: " + "; ".join(problems)))


def print_table(rows):
    header = ("No", "Scenario", "Endpoint", "Status", "Data changed?", "As expected")
    widths = [max(len(str(r[i])) for r in [header, *rows]) for i in range(len(header))]
    def format_row(r):
        return " | ".join(str(c).ljust(w) for c, w in zip(r, widths)).rstrip()
    print(format_row(header))
    print("-+-".join("-" * w for w in widths))
    for r in rows:
        print(format_row(r))


def run_main_cases():
    rows = MAIN_ROWS
    admin, d1, d2, nurse = (valid_token("A-001", "admin"), valid_token("D-001", "doctor"),
                            valid_token("D-002", "doctor"), valid_token("N-001", "nurse"))
    rx = "RX-1001"
    run_case(rows, 1, "Admin A-001 writes RX-1001 (IDOR scenario)", "PUT", V1, rx, admin, EDIT, 200, True)
    run_case(rows, 2, "Admin A-001 writes RX-1001", "PUT", RBAC, rx, admin, EDIT, 403, False)
    run_case(rows, 3, "Admin A-001 writes RX-1001", "PUT", V2, rx, admin, EDIT, 403, False,
             reason="role_lacks_permission")
    run_case(rows, 4, "D-002 (not treating P-01) writes RX-1001", "PUT", V1, rx, d2, EDIT, 200, True)
    run_case(rows, 5, "D-002 writes RX-1001: RBAC only, IDOR open", "PUT", RBAC, rx, d2, EDIT, 200, True)
    run_case(rows, 6, "D-002 writes RX-1001", "PUT", V2, rx, d2, EDIT, 403, False,
             reason="patient_not_treated")
    run_case(rows, 7, "Positive control: D-001 writes RX-1001", "PUT", V2, rx, d1, EDIT, 200, True,
             reason="write_allowed")
    run_case(rows, 8, "Nurse N-001 writes RX-1001", "PUT", V2, rx, nurse, EDIT, 403, False,
             reason="role_lacks_permission")
    run_case(rows, 9, "Nurse N-001 reads RX-1001", "GET", V2, rx, nurse, None, 200, False,
             reason="read_allowed")
    # Kasus 11, 12, 14-16 memakai dokter yang merawat P-01: tanpa cacat token, permintaan lolos.
    # Kasus 13 memakai perawat: status 401 (bukan 403) membuktikan penolakan di tahap token.
    run_case(rows, 10, "No token", "PUT", V2, rx, None, EDIT, 401, False, reason="invalid_token")
    run_case(rows, 11, "Expired token", "PUT", V2, rx, api.make_token("D-001", "doctor", -60), EDIT,
             401, False, reason="invalid_token")
    run_case(rows, 12, "Tampered signature", "PUT", V2, rx, tampered_signature(d1), EDIT, 401, False,
             reason="invalid_token")
    run_case(rows, 13, "Payload role changed to doctor without re-signing", "PUT", V2, rx,
             changed_role(nurse, "doctor"), EDIT, 401, False, reason="invalid_token")
    run_case(rows, 14, "Token alg:none without signature", "PUT", V2, rx,
             alg_none_token("D-001", "doctor"), EDIT, 401, False, reason="invalid_token")
    run_case(rows, 15, "Wrong aud", "PUT", V2, rx, api.make_token("D-001", "doctor", 300, aud="other-api"),
             EDIT, 401, False, reason="invalid_token")
    run_case(rows, 16, "Wrong iss", "PUT", V2, rx, api.make_token("D-001", "doctor", 300, iss="fake-idp"),
             EDIT, 401, False, reason="invalid_token")
    run_case(rows, 17, "Mass assignment: dose + patient_id", "PUT", V2, rx, d1,
             {"dose": "x", "patient_id": "P-03"}, 400, False, reason="field_rejected")
    run_case(rows, 18, "Nonexistent ID, body identical to case 6", "PUT", V2, "RX-9999", d1, EDIT, 403, False,
             reason="object_not_found", check=lambda content: content == RESULTS[6]["content"])


def is_iso8601(text):
    try:
        time.strptime(text, "%Y-%m-%dT%H:%M:%SZ")
        return True
    except (ValueError, TypeError):
        return False


def check_audit():
    """Kasus 19. Mengembalikan (hitungan keputusan, daftar masalah); daftar kosong berarti sesuai."""
    problems = []
    records = [json.loads(x) for x in api.AUDIT]
    counts = collections.Counter(r.get("decision") for r in records)
    # Permintaan /v2 pada kasus 1-18: 14 keputusan, 2 allow (kasus 7, 9), 12 deny.
    if counts != {"allow": 2, "deny": 12}:
        problems.append(f"expected allow=2 deny=12, got {dict(counts)}")
    if any(set(r) != AUDIT_FIELDS for r in records):
        problems.append("record fields incomplete")
    elif not all(is_iso8601(r["time"]) for r in records):
        problems.append("wrong time format")
    case6 = RESULTS[6]["audit"]
    if not (len(case6) == 1 and case6[0].get("sub") == "D-002"
            and case6[0].get("object") == "RX-1001" and case6[0].get("decision") == "deny"):
        problems.append("deny record of case 6 not found")
    return counts, problems


def print_key_evidence():
    print("\nKey evidence (values from server storage):")
    for no, label in ((5, "rbac-only, D-002"), (6, "v2, D-002"), (7, "v2, D-001")):
        r = RESULTS[no]
        print(f"  Case {no} ({label}): status {r['status']}, RX-1001.dose "
              f"{r['before']['RX-1001']['dose']!r} -> {r['after']['RX-1001']['dose']!r}")
    print(f"  Case 6  body: {RESULTS[6]['content']!r}")
    print(f"  Case 18 body: {RESULTS[18]['content']!r}")
    print(f"  Identical byte for byte: {RESULTS[6]['content'] == RESULTS[18]['content']}")


def print_audit(counts):
    print(f"\nAudit /v2 cases 1-18: allow={counts['allow']} deny={counts['deny']}")
    print("  Example deny  (case 6):", json.dumps(RESULTS[6]["audit"][:1]))
    print("  Example allow (case 7):", json.dumps(RESULTS[7]["audit"][:1]))


def check_startup_key(rows, no, scenario, length, expect_success):
    """Mencoba benar-benar membuat server di proses terpisah dengan kunci sepanjang `length`."""
    env = {**os.environ, "SIMRS_JWT_KEY": "k" * length}
    process = subprocess.run(
        [sys.executable, "-c", "import simrs_api; simrs_api.make_server(port=0).server_close()"],
        env=env, capture_output=True, text=True)
    as_expected = (process.returncode == 0) == expect_success
    rows.append((no, scenario, "make_server()", f"rc={process.returncode}", "-",
                 "YES" if as_expected else "NO"))


def run_extra_tests():
    """Perilaku yang disyaratkan tetapi tidak terbedakan oleh 19 kasus utama."""
    rows = EXTRA_ROWS
    d1, d2, admin, nurse = (valid_token("D-001", "doctor"), valid_token("D-002", "doctor"),
                            valid_token("A-001", "admin"), valid_token("N-001", "nurse"))
    rx, same = "RX-1001", lambda content: content == RESULTS[6]["content"]
    forbidden = {"patient_id": "P-03"}
    run_case(rows, "T1", "alg:none + valid HMAC: only the alg check rejects", "PUT", V2, rx,
             alg_none_token("D-001", "doctor", valid_signature=True), EDIT, 401, False,
             reason="invalid_token")
    run_case(rows, "T2", "Order: no token + forbidden field", "PUT", V2, rx, None, forbidden, 401, False,
             reason="invalid_token")
    run_case(rows, "T3", "Order: admin + forbidden field", "PUT", V2, rx, admin, forbidden, 403, False,
             reason="role_lacks_permission")
    run_case(rows, "T4", "Order: D-002 + forbidden field", "PUT", V2, rx, d2, forbidden, 403, False,
             reason="patient_not_treated", check=same)
    run_case(rows, "T5", "D-001 sends malformed JSON", "PUT", V2, rx, d1, b"{not json", 400, False,
             reason="field_rejected")
    run_case(rows, "T6", "D-001 writes notes (second allow-list entry)", "PUT", V2, rx, d1,
             {"notes": "kontrol 7 hari"}, 200, True, reason="write_allowed")
    run_case(rows, "T7", "D-002 reads RX-1001", "GET", V2, rx, d2, None, 403, False,
             reason="patient_not_treated", check=same)
    run_case(rows, "T8", "D-001 reads RX-1001", "GET", V2, rx, d1, None, 200, False,
             reason="read_allowed")
    run_case(rows, "T9", "Nurse reads RX-9999, body identical to case 6", "GET", V2, "RX-9999", nurse,
             None, 403, False, reason="object_not_found", check=same)
    # sub D-001 merawat P-01, jadi hanya cek peran yang bisa menolak token ini.
    run_case(rows, "T10", "Unknown role, sub D-001", "PUT", V2, rx, valid_token("D-001", "head"), EDIT,
             403, False, reason="role_lacks_permission")
    run_case(rows, "T11", "Unknown role, sub D-001", "PUT", RBAC, rx, valid_token("D-001", "head"), EDIT,
             403, False)
    run_case(rows, "T12", "Nurse + header X-Role: doctor", "PUT", V2, rx, nurse,
             {**EDIT, "role": "doctor"}, 403, False, reason="role_lacks_permission",
             headers={"X-Role": "doctor"})
    check_startup_key(rows, "T13", "Key 31 bytes: server refuses to start", 31, False)
    check_startup_key(rows, "T14", "Key 32 bytes: server starts", 32, True)


def main():
    server = api.make_server(HOST, PORT)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    api.AUDIT.clear()
    try:
        run_main_cases()
        counts, audit_problems = check_audit()
        MAIN_ROWS.append((19, "Audit: deny of case 6 (D-002, RX-1001)", "AUDIT /v2", "-", "-",
                          "YES" if not audit_problems else "NO: " + "; ".join(audit_problems)))
        print("MAIN TABLE")
        print_table(MAIN_ROWS)
        print_key_evidence()
        print_audit(counts)
        run_extra_tests()
        print("\nEXTRA TESTS (outside the 19 cases)")
        print_table(EXTRA_ROWS)
    finally:
        server.shutdown()
        server.server_close()
        thread.join()

    rows = MAIN_ROWS + EXTRA_ROWS
    failed = [r[0] for r in rows if r[5] != "YES"]
    print(f"\nSummary: main {sum(r[5] == 'YES' for r in MAIN_ROWS)}/{len(MAIN_ROWS)}, "
          f"extra {sum(r[5] == 'YES' for r in EXTRA_ROWS)}/{len(EXTRA_ROWS)}"
          + (f", FAILED: {failed}" if failed else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
