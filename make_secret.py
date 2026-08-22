#!/usr/bin/env python3
"""
make_secret.py -- encrypts a short secret (a URL, a code) so a stage page can
carry it without shipping it in plaintext.

An in-page gate used to compare the typed answer against a stored PBKDF2 hash
and then reveal a hardcoded destination. The destination sat in the HTML in
clear text, so anyone could read it straight out of devtools and skip the
puzzle -- the gate only hid the link visually, it never protected it.

Encrypting the destination removes the plaintext AND the separate hash: an
AES-GCM authentication tag only verifies under the right key, so a successful
decrypt IS the answer check. One secret, one mechanism, nothing to keep in sync.

Usage:
    python3 make_secret.py <answer> <secret>

Prints a JS object literal to paste into the stage's HTML. The salt is random
per secret, so re-running produces a different (equally valid) blob.

Crypto matches build.py and unlock.js exactly: PBKDF2-HMAC-SHA256 -> AES-256-GCM.
"""
import json
import os
import sys

from build import PBKDF2_ITERATIONS, SALT_LEN, derive_key, encrypt_html, normalize
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit(__doc__.strip())
    answer, secret = sys.argv[1], sys.argv[2]

    salt = os.urandom(SALT_LEN)
    key = derive_key(normalize(answer), salt)
    # encrypt_html() is named for its main caller but encrypts any UTF-8 string.
    payload = encrypt_html(secret, key, salt)

    # Round-trip before printing: a blob that doesn't decrypt would lock the
    # stage permanently, and the failure would only show up in a browser.
    check = AESGCM(key).decrypt(
        base64.b64decode(payload["iv"]), base64.b64decode(payload["ciphertext"]), None
    ).decode("utf-8")
    assert check == secret, "round-trip failed"

    wrong = derive_key(normalize(answer + "x"), salt)
    try:
        AESGCM(wrong).decrypt(
            base64.b64decode(payload["iv"]), base64.b64decode(payload["ciphertext"]), None
        )
        raise SystemExit("FAIL: a wrong answer decrypted the secret")
    except Exception:
        pass

    print(f"  var SECRET = {json.dumps(payload)};")
    print()
    print(f"  round-trip OK ({len(secret)} chars), wrong answer rejected.")


if __name__ == "__main__":
    main()
