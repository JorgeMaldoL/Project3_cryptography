#!/usr/bin/env python3
"""
tofu.py

Trust-on-first-use store for peer public keys.

Saves to ~/.encchat/known_peers.json and looks like:

    {
        "bob": {
            "fingerprint": "9b:d4:22:...",
            "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
            "first_seen": "2026-05-19T12:34:56Z",
            "verified": false
        }
    }

verified starts as false. It only becomes true after the user manually checks
the fingerprint through a separate channel (phone call, in-person, etc).
"""

import json
from datetime import datetime, timezone
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives import serialization, hashes

import paths


def now_iso() -> str:
    # get current time as ISO string
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def fingerprint_of_pem(pem_data: bytes) -> str:
    # get fingerprint from pem key data (sha-256, first 16 bytes)
    key = serialization.load_pem_public_key(pem_data)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("not an ed25519 public key")
    
    raw = key.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(raw)
    short = digest.finalize()[:16]
    return ":".join(f"{b:02x}" for b in short)


def load_store() -> dict:
    # load known_peers.json, return empty dict if missing
    path = paths.known_peers_path()
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        # file got corrupted, just return empty
        return {}


def save_store(store: dict) -> None:
    # write store to known_peers.json
    path = paths.known_peers_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(store, indent=2), encoding="utf-8")


def get_peer(username: str) -> Optional[dict]:
    # get peer entry or none if we don't know them
    return load_store().get(username)


def record_peer(username: str, public_key_pem: bytes) -> dict:
    # add new peer to store (not verified yet)
    fp = fingerprint_of_pem(public_key_pem)
    entry = {
        "fingerprint": fp,
        "public_key_pem": public_key_pem.decode("utf-8"),
        "first_seen": now_iso(),
        "verified": False,
    }
    store = load_store()
    store[username] = entry
    save_store(store)
    return entry


def mark_verified(username: str) -> bool:
    # user verified the fingerprint, mark them as trusted
    store = load_store()
    if username not in store:
        return False
    store[username]["verified"] = True
    save_store(store)
    return True


def fingerprint_matches(username: str, public_key_pem: bytes) -> Optional[bool]:
    # check if incoming key matches what we have stored
    # none = don't know them, true = match, false = mismatch (mitm?)
    entry = get_peer(username)
    if entry is None:
        return None
    return entry["fingerprint"] == fingerprint_of_pem(public_key_pem)
