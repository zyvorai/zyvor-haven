#!/usr/bin/env python3
"""Generates pbkdf2_vectors.json with Python's hashlib.pbkdf2_hmac, independent
of any Go code. Run from this directory:
    python3 -I gen_pbkdf2_vectors.py > pbkdf2_vectors.json
Salts are fixed so the output is reproducible."""
import base64, hashlib, json

# (keycloak algorithm, hashlib name, iterations, derived key length in bytes)
CASES = [
    ("pbkdf2",        "sha1",   20000,  64),
    ("pbkdf2",        "sha1",   27500,  20),
    ("pbkdf2-sha256", "sha256", 27500,  32),
    ("pbkdf2-sha256", "sha256", 210000, 32),
    ("pbkdf2-sha512", "sha512", 30000,  64),
    ("pbkdf2-sha512", "sha512", 210000, 64),
]
PASSWORDS = ["S3cret-pass-1", "pässwörd-über-日本語-\U0001F511", "x", "with space and $dollar"]
SALTS = ["00112233445566778899aabbccddeeff", "a1b2c3d4e5f60718293a4b5c6d7e8f90",
         "0f1e2d3c4b5a69788796a5b4c3d2e1f0", "deadbeefcafebabe0123456789abcdef"]

out = []
n = 0
for alg, h, it, klen in CASES:
    for pw in PASSWORDS:
        salt = bytes.fromhex(SALTS[n % len(SALTS)])
        n += 1
        dk = hashlib.pbkdf2_hmac(h, pw.encode("utf-8"), salt, it, klen)
        sb, vb = base64.b64encode(salt).decode(), base64.b64encode(dk).decode()
        out.append({
            "algorithm": alg, "hash": h, "iterations": it, "keyLen": klen,
            "password": pw,
            "salt_b64_padded": sb, "value_b64_padded": vb,
            "phc": "$pbkdf2-%s$i=%d$%s$%s" % (h, it, sb.rstrip("="), vb.rstrip("=")),
        })
print(json.dumps(out, indent=1, ensure_ascii=True))
