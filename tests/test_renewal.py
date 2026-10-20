import base64
import json

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from authev_core import renewal
from authev_core.errors import CoreFormatError, CoreVerifyError
from authev_core.primitives import canonical_json

NOW = 1_800_000_000
CSR = b"\x30\x82fake-csr-der"
FP = "fp-abc123"
NONCE = b"\x01" * 16
CHAL = "challenge-xyz"


@pytest.fixture(scope="module")
def tpm_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def pub_der(tpm_key):
    return tpm_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


@pytest.fixture(scope="module")
def sign(tpm_key):
    def _sign(data: bytes) -> bytes:
        return tpm_key.sign(
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.DIGEST_LENGTH),
            hashes.SHA256(),
        )
    return _sign


@pytest.fixture
def blob(sign):
    return renewal.build_pop(
        csr_der=CSR, fingerprint=FP, nonce=NONCE, challenge=CHAL, now=NOW, sign=sign
    )


def verify(blob, pub_der, **kw):
    args = dict(tpm_pub_der=pub_der, expect_challenge=CHAL, max_age_s=300, now=NOW + 10)
    args.update(kw)
    return renewal.verify_pop(blob, **args)


def test_round_trip(blob, pub_der):
    req = verify(blob, pub_der)
    assert req.csr_der == CSR
    assert req.fingerprint == FP
    assert req.nonce == NONCE
    assert req.challenge == CHAL
    assert req.ts == NOW
    assert decode_equal(blob, req)


def decode_equal(blob, req):
    return renewal.decode_pop(blob) == req


def test_payload_shape(blob):
    d = json.loads(blob)
    assert set(d) == {"v", "csr", "fp", "nonce", "challenge", "ts", "sig"}
    assert d["v"] == 1
    assert base64.b64decode(d["csr"]) == CSR
    assert base64.b64decode(d["nonce"]) == NONCE
    assert blob == canonical_json(d)


@pytest.mark.parametrize("field,value", [
    ("csr", base64.b64encode(b"other").decode()),
    ("fp", "other-fp"),
    ("nonce", base64.b64encode(b"\x02" * 16).decode()),
    ("challenge", "other-challenge"),
    ("ts", NOW + 1),
])
def test_tampered_field_is_bad_sig(blob, pub_der, field, value):
    d = json.loads(blob)
    d[field] = value
    with pytest.raises(CoreVerifyError, match="^bad_sig$"):
        verify(canonical_json(d), pub_der, expect_challenge=d["challenge"])


def test_wrong_key_is_bad_sig(blob):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other_der = other.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with pytest.raises(CoreVerifyError, match="^bad_sig$"):
        verify(blob, other_der)


def test_garbage_sig_is_bad_sig(blob, pub_der):
    d = json.loads(blob)
    d["sig"] = base64.b64encode(b"junk").decode()
    with pytest.raises(CoreVerifyError, match="^bad_sig$"):
        verify(canonical_json(d), pub_der)


def test_wrong_challenge(blob, pub_der):
    with pytest.raises(CoreVerifyError, match="^bad_challenge$"):
        verify(blob, pub_der, expect_challenge="nope")


def test_stale(blob, pub_der):
    with pytest.raises(CoreVerifyError, match="^stale$"):
        verify(blob, pub_der, now=NOW + 301)


def test_age_at_limit_ok(blob, pub_der):
    verify(blob, pub_der, now=NOW + 300)


def test_truncated_is_format_error(blob, pub_der):
    with pytest.raises(CoreFormatError):
        renewal.decode_pop(blob[:-5])
    with pytest.raises(CoreFormatError):
        verify(blob[:-5], pub_der)


def test_garbage_is_format_error():
    for bad in (b"", b"\xff\xfe", b"[]", b"123"):
        with pytest.raises(CoreFormatError):
            renewal.decode_pop(bad)


def test_unsupported_version(blob):
    d = json.loads(blob)
    d["v"] = 2
    with pytest.raises(CoreFormatError):
        renewal.decode_pop(canonical_json(d))


@pytest.mark.parametrize("mutate", [
    lambda d: d.pop("sig"),
    lambda d: d.pop("fp"),
    lambda d: d.__setitem__("ts", "123"),
    lambda d: d.__setitem__("ts", True),
    lambda d: d.__setitem__("fp", 5),
    lambda d: d.__setitem__("csr", "!!notb64!!"),
    lambda d: d.__setitem__("nonce", 7),
])
def test_wrong_type_or_missing_is_format_error(blob, mutate):
    d = json.loads(blob)
    mutate(d)
    with pytest.raises(CoreFormatError):
        renewal.decode_pop(canonical_json(d))
