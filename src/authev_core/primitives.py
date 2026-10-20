"""AES-256-GCM, Ed25519, Argon2id and canonical JSON primitives."""

import json
import os

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import CoreFormatError, CoreVerifyError

NONCE_LEN = 12
KEY_LEN = 32

ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST_KIB = 65536
ARGON2_PARALLELISM = 4


def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """Return nonce(12) || ciphertext||tag."""
    nonce = os.urandom(NONCE_LEN)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def aes_gcm_decrypt(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    if len(blob) < NONCE_LEN + 16:
        raise CoreFormatError("AES-GCM blob too short")
    nonce, ct = blob[:NONCE_LEN], blob[NONCE_LEN:]
    try:
        return AESGCM(key).decrypt(nonce, ct, aad)
    except InvalidTag as e:
        raise CoreVerifyError("AES-GCM authentication failed") from e


def ed25519_sign(priv: Ed25519PrivateKey, msg: bytes) -> bytes:
    return priv.sign(msg)


def ed25519_verify(pub: Ed25519PublicKey, msg: bytes, sig: bytes) -> None:
    try:
        pub.verify(sig, msg)
    except InvalidSignature as e:
        raise CoreVerifyError("Ed25519 signature invalid") from e


def derive_key_argon2id(passphrase: str, salt: bytes) -> bytes:
    return hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST_KIB,
        parallelism=ARGON2_PARALLELISM,
        hash_len=KEY_LEN,
        type=Type.ID,
    )


def canonical_json(obj: dict) -> bytes:
    """Signing serialization: sorted keys, no whitespace, UTF-8."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
