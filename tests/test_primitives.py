import os

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from authev_core.errors import CoreVerifyError
from authev_core.primitives import (
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    canonical_json,
    derive_key_argon2id,
    ed25519_sign,
    ed25519_verify,
)


def test_aes_gcm_round_trip():
    key = os.urandom(32)
    blob = aes_gcm_encrypt(key, b"hello", b"aad")
    assert len(blob) == 12 + 5 + 16
    assert aes_gcm_decrypt(key, blob, b"aad") == b"hello"


def test_aes_gcm_altered_ciphertext_fails():
    key = os.urandom(32)
    blob = bytearray(aes_gcm_encrypt(key, b"hello"))
    blob[-1] ^= 1
    with pytest.raises(CoreVerifyError):
        aes_gcm_decrypt(key, bytes(blob))


def test_aes_gcm_wrong_aad_fails():
    key = os.urandom(32)
    blob = aes_gcm_encrypt(key, b"hello", b"aad")
    with pytest.raises(CoreVerifyError):
        aes_gcm_decrypt(key, blob, b"other")


def test_ed25519_round_trip_and_flipped_bit():
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    sig = ed25519_sign(priv, b"msg")
    ed25519_verify(pub, b"msg", sig)
    bad = bytearray(sig)
    bad[0] ^= 1
    with pytest.raises(CoreVerifyError):
        ed25519_verify(pub, b"msg", bytes(bad))


def test_canonical_json():
    assert canonical_json({"b": 1, "a": 2}) == b'{"a":2,"b":1}'


def test_argon2id_deterministic_and_salt_sensitive():
    a = derive_key_argon2id("pw", b"s" * 16)
    assert len(a) == 32
    assert a == derive_key_argon2id("pw", b"s" * 16)
    assert a != derive_key_argon2id("pw", b"t" * 16)
