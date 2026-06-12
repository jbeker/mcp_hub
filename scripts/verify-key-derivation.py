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
    import hashlib as h

    ctx_nul = CONTEXT + b"\x00"
    out: dict[str, bytes] = {
        # No derivation.
        "raw master key": master,
        # Full HKDF (extract+expand), every salt/info placement.
        'HKDF(salt="", ikm=master, info=CONTEXT)': hkdf_sha256(master, b"", CONTEXT),
        'HKDF(salt=CONTEXT, ikm=master, info="")': hkdf_sha256(master, CONTEXT, b""),
        "HKDF(salt=CONTEXT, ikm=master, info=CONTEXT)": hkdf_sha256(master, CONTEXT, CONTEXT),
        "HKDF-Expand-only(prk=master, info=CONTEXT)": hkdf_expand(master, CONTEXT),
        # Plain single HMAC-SHA256 (no HKDF counter byte) — both key/msg orders,
        # with and without a trailing NUL on the context.
        "HMAC(key=master, msg=CONTEXT)": hmac.new(master, CONTEXT, hashlib.sha256).digest(),
        "HMAC(key=master, msg=CONTEXT+NUL)": hmac.new(master, ctx_nul, hashlib.sha256).digest(),
        "HMAC(key=CONTEXT, msg=master)": hmac.new(CONTEXT, master, hashlib.sha256).digest(),
        "HMAC(key=CONTEXT+NUL, msg=master)": hmac.new(ctx_nul, master, hashlib.sha256).digest(),
        # Plain SHA-256 of concatenations.
        "SHA256(CONTEXT || master)": h.sha256(CONTEXT + master).digest(),
        "SHA256(master || CONTEXT)": h.sha256(master + CONTEXT).digest(),
        "SHA256(CONTEXT+NUL || master)": h.sha256(ctx_nul + master).digest(),
        "SHA256(master || CONTEXT+NUL)": h.sha256(master + ctx_nul).digest(),
        "SHA256(master)": h.sha256(master).digest(),
    }
    return out


# Associated-data candidates tried for every key (the seal may bind the row's
# identity into the AEAD tag). Filled per-row in check_row.
def aad_variants(instance_id: str, key_name: str) -> dict[str, bytes]:
    return {
        "": b"",
        "key_name": key_name.encode(),
        "instance_id": instance_id.encode(),
        "instance_id/key_name": f"{instance_id}/{key_name}".encode(),
        "CONTEXT": CONTEXT,
    }


def try_open(key: bytes, aad: bytes, nonce: bytes, ciphertext: bytes) -> bool:
    try:
        crypto_aead_xchacha20poly1305_ietf_decrypt(ciphertext, aad, nonce, key)
        return True
    except Exception:
        return False


def check_row(
    label: str,
    nonce: bytes,
    ciphertext: bytes,
    keys: dict[str, bytes],
    aads: dict[str, bytes],
) -> list[str]:
    if len(nonce) != NONCE_LEN:
        print(f"  {label}: SKIP (nonce is {len(nonce)} bytes, expected {NONCE_LEN})")
        return []
    hits = []
    for kname, key in keys.items():
        for aname, aad in aads.items():
            if try_open(key, aad, nonce, ciphertext):
                hits.append(f"{kname}" + (f" [aad={aname}]" if aad else ""))
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
        all_hits.update(check_row(f"{inst}/{key_name}", nonce, ct, keys, aad_variants(inst, key_name)))

    print("instance_config_files:")
    rows = db.execute(
        "SELECT instance_id, nonce, ciphertext FROM instance_config_files LIMIT 20"
    ).fetchall()
    if not rows:
        print("  (none)")
    for inst, nonce, ct in rows:
        all_hits.update(check_row(inst, nonce, ct, keys, aad_variants(inst, "")))

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
        all_hits.update(check_row(kid, blob[:NONCE_LEN], blob[NONCE_LEN:], keys, aad_variants(kid, "")))

    print()
    if len(all_hits) == 1:
        print(f"RESULT: construction is -> {next(iter(all_hits))}")
    elif not all_hits:
        print("RESULT: NOTHING matched. Either HUB_MASTER_KEY is not the key that "
              "sealed this DB, or the construction is none of those tried.")
    else:
        print(f"RESULT: multiple matched (pick the non-raw one if present): {sorted(all_hits)}")
    return 0


if __name__ == "__main__":
    main()
    sys.exit(0)
