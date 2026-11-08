"""Simulasi API resep SIMRS (lab sintetis): /v1 rentan, /rbac-only, /v2 aman."""
import base64, hashlib, hmac, json, os, time
from http.server import BaseHTTPRequestHandler, HTTPServer

ISS, AUD = "simrs-idp-lab", "simrs-prescription-api"
ROLE_PERMISSIONS = {"doctor": {"prescription:read", "prescription:write"},
                    "nurse": {"prescription:read"},
                    "admin": {"schedule:read"}}  # Peran tak dikenal: deny by default.
DOCTOR_PATIENTS = {"D-001": {"P-01", "P-02"}, "D-002": {"P-03"}}  # Relasi hanya ada di server.
INITIAL_PRESCRIPTIONS = {
    "RX-1001": {"patient": "P-01", "drug": "Amoksisilin", "dose": "500 mg 3x1"},
    "RX-1002": {"patient": "P-02", "drug": "Metformin", "dose": "500 mg 2x1"},
    "RX-2001": {"patient": "P-03", "drug": "Amlodipin", "dose": "5 mg 1x1"}}
ALLOWED_FIELDS = {"dose", "notes"}  # Allow-list /v2: mencegah mass assignment.
PRESCRIPTIONS, AUDIT = {}, []  # Data di memori; AUDIT berisi baris JSON Lines.
BODY_400 = b'{"error":"invalid request"}'
BODY_401 = b'{"error":"invalid token"}'
BODY_403 = b'{"error":"access denied"}'  # Sama untuk ID tak ada dan bukan pasien Anda.

def reset_data():
    PRESCRIPTIONS.update({rid: dict(content) for rid, content in INITIAL_PRESCRIPTIONS.items()})

def jwt_key():
    if len(value := os.environ.get("SIMRS_JWT_KEY", "").encode()) < 32:
        raise SystemExit("SIMRS_JWT_KEY is required, minimum 32 bytes; server will not start.")
    return value

def b64u(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def b64u_decode(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))

def sign(signing_input, hmac_key):
    return b64u(hmac.new(hmac_key, signing_input, hashlib.sha256).digest())

def make_token(sub, role, exp_offset, aud=AUD, iss=ISS):  # Hanya harness uji (IdP).
    claims = {"sub": sub, "role": role, "iss": iss, "aud": aud,
              "exp": int(time.time()) + exp_offset}
    h = b64u(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    p = b64u(json.dumps(claims).encode())
    return f"{h}.{p}.{sign(f'{h}.{p}'.encode(), jwt_key())}"

def validate_token(token):  # Satu-satunya sumber peran. Gagal apa pun: None.
    try:
        h, p, s = token.split(".")  # Selain tepat 3 bagian memicu ValueError.
        # RFC 8725 s3.1: alg harus persis HS256 SEBELUM verifikasi; none ditolak.
        if json.loads(b64u_decode(h)).get("alg") != "HS256":
            return None
        expected = sign(f"{h}.{p}".encode("ascii"), jwt_key())
        if not hmac.compare_digest(expected.encode(), s.encode()):
            return None
        claims = json.loads(b64u_decode(p))
        # RFC 9068 s4: exp, iss, dan aud wajib diperiksa.
        valid = (time.time() < claims["exp"] and claims["iss"] == ISS and claims["aud"] == AUD
                 and isinstance(claims["sub"], str) and isinstance(claims["role"], str))
        return claims if valid else None
    except (ValueError, AttributeError, TypeError, KeyError):
        return None

def parse_json(body):
    try:
        data = json.loads(body)
    except (ValueError, RecursionError):
        return None
    return data if isinstance(data, dict) else None

def evaluate_vulnerable(version, claims, rid, body):  # /v1 dan /rbac-only: tanpa cek objek.
    if not claims:
        return 401, BODY_401
    if version == "rbac-only" and "prescription:write" not in ROLE_PERMISSIONS.get(claims["role"], ()):
        return 403, BODY_403
    if rid not in PRESCRIPTIONS or (data := parse_json(body)) is None:
        return 400, BODY_400
    PRESCRIPTIONS[rid].update(data)  # RENTAN: isi body ditulis apa adanya ke resep siapa pun.
    return 200, json.dumps(PRESCRIPTIONS[rid]).encode()

def evaluate_v2(claims, action, rid, body):  # Hasil: (status, body, decision, reason).
    if not claims:  # Langkah 1: token.
        return 401, BODY_401, "deny", "invalid_token"
    if action not in ROLE_PERMISSIONS.get(claims["role"], ()):  # Langkah 2: izin peran.
        return 403, BODY_403, "deny", "role_lacks_permission"
    # Langkah 3: objek. Penyederhanaan lab: perawat boleh MEMBACA resep pasien mana pun.
    nurse_read = claims["role"] == "nurse" and action == "prescription:read"
    prescription = PRESCRIPTIONS.get(rid)
    if prescription is None:
        return 403, BODY_403, "deny", "object_not_found"
    if not nurse_read and prescription["patient"] not in DOCTOR_PATIENTS.get(claims["sub"], ()):
        return 403, BODY_403, "deny", "patient_not_treated"
    if action == "prescription:read":
        return 200, json.dumps(prescription).encode(), "allow", "read_allowed"
    data = parse_json(body)  # Langkah 4: allow-list field.
    if not data or set(data) - ALLOWED_FIELDS:
        return 400, BODY_400, "deny", "field_rejected"
    prescription.update(data)  # Langkah 5: terapkan perubahan.
    return 200, json.dumps(prescription).encode(), "allow", "write_allowed"

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_): pass  # Keputusan keamanan dicatat di AUDIT, bukan stderr.

    def respond(self, status, content):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(content)))
        if status == 401:
            self.send_header("WWW-Authenticate", "Bearer")
        self.end_headers()
        self.wfile.write(content)

    def dispatch(self, action, body=b""):
        parts = self.path.split("?")[0].split("/")
        is_route = len(parts) == 4 and parts[2] == "prescriptions"
        version, rid = (parts[1], parts[3]) if is_route else (None, None)
        scheme, _, token = self.headers.get("Authorization", "").partition(" ")
        claims = (validate_token(token) if scheme.lower() == "bearer" else None) or {}
        if version == "v2":
            status, content, decision, reason = evaluate_v2(claims, action, rid, body)
            AUDIT.append(json.dumps(dict(time=time.strftime("%FT%TZ", time.gmtime()),
                sub=claims.get("sub"), role=claims.get("role"), action=action, object=rid,
                decision=decision, reason=reason)))  # Langkah 6: audit semua.
            self.respond(status, content)
        elif version in ("v1", "rbac-only") and action == "prescription:write":
            self.respond(*evaluate_vulnerable(version, claims, rid, body))
        else:
            self.send_error(404)

    def do_GET(self):
        self.dispatch("prescription:read")

    def do_PUT(self):
        length = self.headers.get("Content-Length", "0")
        body = self.rfile.read(min(int(length), 65536)) if length.isdigit() else b""
        self.dispatch("prescription:write", body)

def make_server(host="127.0.0.1", port=18080):
    jwt_key()  # Menolak start bila kunci kosong atau kurang dari 32 byte.
    reset_data()
    return HTTPServer((host, port), Handler)  # Serial: cek lalu tulis tak berbalapan.

if __name__ == "__main__":
    make_server().serve_forever()
