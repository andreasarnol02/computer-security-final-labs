#!/usr/bin/env python3
"""Uji jawaban-diketahui (KAT) primitif AES-256-GCM: McGrew & Viega, Test Case 14."""
import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

K = bytes(32)    # kunci 256-bit nol
IV = bytes(12)   # nonce 96-bit nol
P = bytes(16)    # plaintext 16 byte nol, tanpa AAD
C_EXPECTED = "cea7403d4d606b6e074ec5d3baf39d18"
T_EXPECTED = "d0d1c8a799996bf0265b98b5d48ab919"

result = AESGCM(K).encrypt(IV, P, None)   # pustaka mengembalikan ciphertext || tag(16)
c, t = result[:16].hex(), result[16:].hex()
print(f"ciphertext  expected={C_EXPECTED} actual={c}")
print(f"tag         expected={T_EXPECTED} actual={t}")
passed = (c == C_EXPECTED and t == T_EXPECTED)
print("PASS" if passed else "FAIL")
sys.exit(0 if passed else 1)
