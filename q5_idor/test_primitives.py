#!/usr/bin/env python3
"""Oracle independen untuk primitif HS256 di simrs_api.py. Keluar nonzero bila ada FAIL."""
import base64, os, secrets, subprocess, sys

# Kunci sekali pakai khusus proses ini, karena O2 harus menaruh kunci di argv openssl.
# Kunci milik run.sh tidak pernah masuk argv maupun pesan galat subprocess.
KEY_O2 = secrets.token_hex(32)
os.environ["SIMRS_JWT_KEY"] = KEY_O2

import simrs_api as api  # noqa: E402

# Vektor RFC 7515 Lampiran A.1.
A1_KEY = "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
A1_INPUT = ("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"
            ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ")
A1_SIGNATURE = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"


def report(name, expected, actual):
    passed = expected == actual
    print(f"{name}: {'PASS' if passed else 'FAIL'}")
    print(f"  expected: {expected}")
    print(f"  actual  : {actual}")
    return passed


def o1_rfc7515_a1():
    # Kunci didekode di sini, bukan oleh simrs_api, agar oracle tidak bergantung pada kode yang diuji.
    key = base64.urlsafe_b64decode(A1_KEY + "=" * (-len(A1_KEY) % 4))
    actual = api.sign(A1_INPUT.encode(), key)
    return report("O1 RFC 7515 A.1 HS256 known answer", A1_SIGNATURE, actual)


def o2_openssl():
    token = api.make_token("D-001", "doctor", 300)
    h, p, s = token.split(".")
    result = subprocess.run(
        ["openssl", "dgst", "-sha256", "-mac", "HMAC", "-macopt", f"hexkey:{KEY_O2.encode().hex()}", "-binary"],
        input=f"{h}.{p}".encode(), capture_output=True)
    if result.returncode != 0 or len(result.stdout) != 32:
        print(f"O2 make_token vs openssl dgst HMAC-SHA256: FAIL (openssl rc={result.returncode})")
        return False
    expected = base64.urlsafe_b64encode(result.stdout).rstrip(b"=").decode()
    return report("O2 make_token vs openssl dgst HMAC-SHA256", expected, s)


def main():
    results = [o1_rfc7515_a1(), o2_openssl()]
    print(f"Oracles passed: {sum(results)}/{len(results)}")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
