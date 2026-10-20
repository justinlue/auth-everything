import base64

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import authev_core
from authev_core import (
    FORMAT_VERSION,
    CoreFormatError,
    CoreVerifyError,
    build_pop,
    check_clock,
    decode_mark,
    decode_pop,
    new_mark,
    unwrap,
    verify_leaf,
    verify_pop,
    wrap,
)
from authev_core.primitives import canonical_json, ed25519_sign


def test_format_version_and_version_string():
    assert FORMAT_VERSION == 1
    assert isinstance(authev_core.__version__, str)


def test_all_names_resolve():
    for name in authev_core.__all__:
        assert hasattr(authev_core, name), name
    assert CoreVerifyError and verify_leaf and build_pop and verify_pop
    assert new_mark and check_clock and wrap and unwrap


def _signed(body: dict, priv: Ed25519PrivateKey) -> bytes:
    body = dict(body)
    body["sig"] = base64.b64encode(ed25519_sign(priv, canonical_json(body))).decode("ascii")
    return canonical_json(body)


def test_every_decoder_rejects_unsupported_version():
    priv = Ed25519PrivateKey.generate()
    b64 = lambda b: base64.b64encode(b).decode("ascii")

    pop = _signed({"v": 2, "csr": b64(b"c"), "fp": "f", "nonce": b64(b"n"),
                   "challenge": "ch", "ts": 1}, priv)
    with pytest.raises(CoreFormatError, match="version"):
        decode_pop(pop)

    mark = _signed({"v": 2, "hw": 5, "src": "server"}, priv)
    with pytest.raises(CoreFormatError, match="version"):
        decode_mark(mark, verify_pub=priv.public_key())

    env = canonical_json({"v": 2, "pid": "p", "ver": "1", "exp": 10, "wk": b64(b"x")})
    with pytest.raises(CoreFormatError, match="version"):
        unwrap(env, product_id="p", now=0, unwrap=lambda ct: b"k")
