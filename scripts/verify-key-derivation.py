# /// script
# requires-python = ">=3.10"
# dependencies = ["pynacl"]
# ///
"""Identify which key derivation the deployed hub used to seal the database.

The deployed image 1e90964 seals secrets with a key derived from
HUB_MASTER_KEY via HKDF-SHA256 and the context string "hub-secretbox-v1"
(recovered from binary strings); the exact HKDF construction (salt vs info,
extract-and-expand vs expand-only) is not knowable from the binary alone.
This script tries every plausible construction against real sealed rows and
reports which one opens them — so the reimplementation can match bit-for-bit.

Run ON the deployment host (no secrets leave the box, nothing is printed
except candidate names):

    docker compose cp hub:/data/hub.db /tmp/hub-check.db
    HUB_MASTER_KEY='<value from compose>' uv run scripts/verify-key-derivation.py /tmp/hub-check.db
    rm /tmp/hub-check.db
"""

import base64
import hashlib
import hmac
import os
import sqlite3
import sys

from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_decrypt

CONTEXT = b"hub-secretbox-v1"
NONCE_LEN = 24


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    prk = hmac.new(salt or b"\x00" * 32, ikm, hashlib.sha256).digest()
    return hkdf_expand(prk, info, length)


def hkdf_expand(prk: bytes, info: bytes, length: int = 32) -> bytes:
    out, block = b"", b""
    counter = 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def candidates(master: bytes) -> dict[str, bytes]:
    return {
        "raw master key (legacy, pre-HKDF)": master,
        'HKDF(salt="", ikm=master, info=CONTEXT)': hkdf_sha256(master, b"", CONTEXT),
        "HKDF(salt=CONTEXT, ikm=master, info=\"\")": hkdf_sha256(master, CONTEXT, b""),
        "HKDF-Expand-only(prk=master, info=CONTEXT)": hkdf_expand(master, CONTEXT),
        "HKDF(salt=CONTEXT, ikm=master, info=CONTEXT)": hkdf_sha256(master, CONTEXT, CONTEXT),
    }


def try_open(key: bytes, nonce: bytes, ciphertext: bytes) -> bool:
    try:
        crypto_aead_xchacha20poly1305_ietf_decrypt(ciphertext, b"", nonce, key)
        return True
    except Exception:
        return False


def check_row(label: str, nonce: bytes, ciphertext: bytes, keys: dict[str, bytes]) -> list[str]:
    if len(nonce) != NONCE_LEN:
        print(f"  {label}: SKIP (nonce is {len(nonce)} bytes, expected {NONCE_LEN})")
        return []
    hits = [name for name, key in keys.items() if try_open(key, nonce, ciphertext)]
    print(f"  {label}: {', '.join(hits) if hits else 'NO candidate opens this row'}")
    return hits


def main() -> int:
    db_path = sys.argv[1] if len(sys.argv) > 1 else "hub.db"
    raw = os.environ.get("HUB_MASTER_KEY", "").strip()
    if not raw:
        print("error: set HUB_MASTER_KEY in the environment", file=sys.stderr)
        return 2
    master = base64.b64decode(raw)
    if len(master) != 32:
        print(f"error: HUB_MASTER_KEY decodes to {len(master)} bytes, expected 32", file=sys.stderr)
        return 2

    keys = candidates(master)
    db = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    all_hits: set[str] = set()

    print("instance_secrets:")
    rows = db.execute(
        "SELECT instance_id, key_name, nonce, ciphertext FROM instance_secrets LIMIT 20"
    ).fetchall()
    if not rows:
        print("  (none)")
    for inst, key_name, nonce, ct in rows:
        all_hits.update(check_row(f"{inst}/{key_name}", nonce, ct, keys))

    print("instance_config_files:")
    rows = db.execute(
        "SELECT instance_id, nonce, ciphertext FROM instance_config_files LIMIT 20"
    ).fetchall()
    if not rows:
        print("  (none)")
    for inst, nonce, ct in rows:
        all_hits.update(check_row(inst, nonce, ct, keys))

    print("oauth_signing_keys:")
    rows = db.execute(
        "SELECT kid, private_pkcs8_b64 FROM oauth_signing_keys WHERE active = 1"
    ).fetchall()
    if not rows:
        print("  (none)")
    for kid, stored in rows:
        if stored.startswith("-----BEGIN"):
            print(f"  {kid}: legacy plaintext PEM (not sealed)")
            continue
        blob = base64.b64decode(stored)
        all_hits.update(check_row(kid, blob[:NONCE_LEN], blob[NONCE_LEN:], keys))

    print()
    derived = sorted(h for h in all_hits if not h.startswith("raw "))
    if len(derived) == 1:
        print(f"RESULT: derived construction is -> {derived[0]}")
    elif not derived:
        print("RESULT: only the raw master key matched (or nothing did) — "
              "the DB may not be in the HKDF format, or the key is wrong.")
    else:
        print(f"RESULT: ambiguous, multiple constructions matched: {derived}")
    if any(h.startswith("raw ") for h in all_hits):
        print("NOTE: some rows still use the raw master key — the reimplementation "
              "must keep raw-key fallback + re-seal-on-read.")
    return 0


if __name__ == "__main__":
    main()
    sys.exit(0)
