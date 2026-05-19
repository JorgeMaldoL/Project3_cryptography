#!/usr/bin/env python3
"""
cryptography_session.py

Authenticated key exchange + session state.

Protocol:
  1. each party generates a fresh ephemeral X25519 key pair per session
  2. each signs (PROTOCOL_VERSION | sender | recipient | ephemeral_pub) with their long-term Ed25519 key
  3. they exchange ephemeral pubkeys + signatures through the relay
  4. each verifies the peer's signature against the peer's long-term key (from TOFU)
  5. shared_secret = X25519(my_ephemeral_priv, peer_ephemeral_pub)
  6. HKDF(shared_secret) -> two 32-byte keys, one per direction

forward secrecy: ephemeral keys live only in memory, discarded after handshake.
"""

import base64
import json
from datetime import datetime, timezone
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature

PROTOCOL_VERSION = b"ENCCHAT-v1"


def transcript(sender: str, recipient: str, ephemeral_pub_bytes: bytes) -> bytes:
    # bytes that get signed: version + sender + recipient + ephemeral pubkey
    # null-byte separator prevents ambiguity attacks between concatenated fields
    sep = b"\x00"
    return PROTOCOL_VERSION + sep + sender.encode() + sep + recipient.encode() + sep + ephemeral_pub_bytes


def generate_ephemeral_keypair() -> Tuple[X25519PrivateKey, bytes]:
    # generate fresh X25519 pair for this session, returns (priv, raw pub bytes)
    priv = X25519PrivateKey.generate()
    pub_bytes = priv.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    return priv, pub_bytes


def x25519_pub_from_bytes(raw: bytes) -> X25519PublicKey:
    return X25519PublicKey.from_public_bytes(raw)


def sign_ephemeral(long_term_priv: Ed25519PrivateKey, sender: str, recipient: str, ephemeral_pub_bytes: bytes) -> bytes:
    # sign the handshake transcript with our long-term identity key
    return long_term_priv.sign(transcript(sender, recipient, ephemeral_pub_bytes))


def verify_ephemeral(peer_long_term_pub: Ed25519PublicKey, sender: str, recipient: str, ephemeral_pub_bytes: bytes, signature: bytes) -> bool:
    # verify sender signed (version, sender, recipient, epk) with their long-term key
    try:
        peer_long_term_pub.verify(signature, transcript(sender, recipient, ephemeral_pub_bytes))
        return True
    except InvalidSignature:
        return False


def derive_session_keys(my_ephemeral_priv: X25519PrivateKey, peer_ephemeral_pub: X25519PublicKey, initiator: str, responder: str) -> Tuple[bytes, bytes]:
    # X25519 DH then HKDF -> two independent 32-byte keys, one per direction
    # returns (initiator->responder key, responder->initiator key)
    shared_secret = my_ephemeral_priv.exchange(peer_ephemeral_pub)
    k_i_to_r = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                    info=PROTOCOL_VERSION + b"|" + initiator.encode() + b"->" + responder.encode()).derive(shared_secret)
    shared_secret_2 = my_ephemeral_priv.exchange(peer_ephemeral_pub)
    k_r_to_i = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                    info=PROTOCOL_VERSION + b"|" + responder.encode() + b"->" + initiator.encode()).derive(shared_secret_2)
    return k_i_to_r, k_r_to_i


def make_handshake_payload(sender: str, recipient: str, ephemeral_pub_bytes: bytes, signature: bytes) -> str:
    # pack handshake as json then base64 - relay sees one opaque blob
    obj = {
        "v": PROTOCOL_VERSION.decode(),
        "from": sender,
        "to": recipient,
        "epk": base64.b64encode(ephemeral_pub_bytes).decode("ascii"),
        "sig": base64.b64encode(signature).decode("ascii"),
    }
    return base64.b64encode(json.dumps(obj).encode("utf-8")).decode("ascii")


def parse_handshake_payload(b64: str) -> dict:
    # inverse of make_handshake_payload, raises ValueError on malformed input
    try:
        obj = json.loads(base64.b64decode(b64, validate=True).decode("utf-8"))
        for k in ("v", "from", "to", "epk", "sig"):
            if k not in obj:
                raise ValueError(f"missing field: {k}")
        if obj["v"] != PROTOCOL_VERSION.decode():
            raise ValueError(f"protocol version mismatch: {obj['v']!r}")
        return {
            "v": obj["v"], "from": obj["from"], "to": obj["to"],
            "epk": base64.b64decode(obj["epk"], validate=True),
            "sig": base64.b64decode(obj["sig"], validate=True),
        }
    except Exception as e:
        raise ValueError(f"malformed handshake payload: {e}")


def new_session(send_key: bytes, recv_key: bytes) -> dict:
    # build session state dict
    return {
        "send_key": send_key,
        "recv_key": recv_key,
        "send_counter": 0,
        "recv_counter": 0,
        "established_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
