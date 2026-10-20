import base64
import json
import os

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from authev_core import assetkey
from authev_core.errors import CoreFormatError, CoreVerifyError

NOW = 1_700_000_000


@pytest.fixture(scope="module")
def tpm():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _pub_der(priv):
    return priv.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def _unwrapper(priv):
    return lambda ct: priv.decrypt(ct, padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))


def _blob(tpm, k_p=None, exp=NOW + 100):
    return assetkey.wrap(k_p=k_p or os.urandom(32), product_id="prod", version="1.0",
                         not_after=exp, tpm_pub_der=_pub_der(tpm))


def test_round_trip_returns_32_byte_key(tpm):
    k_p = os.urandom(32)
    blob = _blob(tpm, k_p)
    out = assetkey.unwrap(blob, product_id="prod", now=NOW, unwrap=_unwrapper(tpm))
    assert out == k_p and len(out) == 32


def test_envelope_shape(tpm):
    d = json.loads(_blob(tpm))
    assert set(d) == {"v", "pid", "ver", "exp", "wk"}
    assert d["v"] == 1 and d["pid"] == "prod" and d["ver"] == "1.0" and d["exp"] == NOW + 100
    assert len(base64.b64decode(d["wk"])) == 256


def test_wrong_product(tpm):
    with pytest.raises(CoreVerifyError, match="wrong_product"):
        assetkey.unwrap(_blob(tpm), product_id="other", now=NOW, unwrap=_unwrapper(tpm))


def test_expired(tpm):
    with pytest.raises(CoreVerifyError, match="expired"):
        assetkey.unwrap(_blob(tpm, exp=NOW - 1), product_id="prod", now=NOW,
                        unwrap=_unwrapper(tpm))


def test_boundary_now_equals_exp_ok(tpm):
    k_p = os.urandom(32)
    blob = _blob(tpm, k_p, exp=NOW)
    assert assetkey.unwrap(blob, product_id="prod", now=NOW, unwrap=_unwrapper(tpm)) == k_p


def test_truncated_and_garbage(tpm):
    blob = _blob(tpm)
    for bad in (blob[:-5], b"", b"\xff\xfe", b"[]", b"null"):
        with pytest.raises(CoreFormatError):
            assetkey.unwrap(bad, product_id="prod", now=NOW, unwrap=_unwrapper(tpm))


def test_unsupported_version(tpm):
    d = json.loads(_blob(tpm))
    d["v"] = 2
    with pytest.raises(CoreFormatError):
        assetkey.unwrap(json.dumps(d).encode(), product_id="prod", now=NOW,
                        unwrap=_unwrapper(tpm))


def test_wrong_types_and_bad_base64(tpm):
    d = json.loads(_blob(tpm))
    for field, val in (("exp", "x"), ("exp", True), ("pid", 1), ("wk", 5), ("wk", "!!!"),
                       ("ver", None)):
        e = dict(d, **{field: val})
        with pytest.raises(CoreFormatError):
            assetkey.unwrap(json.dumps(e).encode(), product_id="prod", now=NOW,
                            unwrap=_unwrapper(tpm))
    e = dict(d)
    del e["wk"]
    with pytest.raises(CoreFormatError):
        assetkey.unwrap(json.dumps(e).encode(), product_id="prod", now=NOW,
                        unwrap=_unwrapper(tpm))


def test_altered_wk_propagates_unwrapper_error(tpm):
    d = json.loads(_blob(tpm))
    ct = bytearray(base64.b64decode(d["wk"]))
    ct[0] ^= 0xFF
    d["wk"] = base64.b64encode(bytes(ct)).decode()
    with pytest.raises(ValueError):
        assetkey.unwrap(json.dumps(d).encode(), product_id="prod", now=NOW,
                        unwrap=_unwrapper(tpm))


def test_wrap_unsupported_key_type_is_format_error():
    from cryptography.hazmat.primitives.asymmetric import ec
    der = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    with pytest.raises(CoreFormatError):
        assetkey.wrap(k_p=b"\0" * 32, product_id="p", version="1", not_after=1, tpm_pub_der=der)
    # DER parsing to an algorithm cryptography does not support
    from cryptography.exceptions import UnsupportedAlgorithm
    from unittest import mock
    from authev_core import primitives
    with mock.patch.object(primitives, "load_der_public_key",
                           side_effect=UnsupportedAlgorithm("x")):
        with pytest.raises(CoreFormatError):
            assetkey.wrap(k_p=b"\0" * 32, product_id="p", version="1", not_after=1,
                          tpm_pub_der=b"x")
