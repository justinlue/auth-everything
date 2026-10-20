import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from authev_core import clockmark
from authev_core.errors import CoreFormatError, CoreVerifyError

HW = 1_800_000_000


@pytest.fixture(scope="module")
def key():
    return Ed25519PrivateKey.generate()


def _mark(key, hw=HW, server=False):
    blob = clockmark.new_mark(hw, server_signed=server, sign_priv=key)
    return clockmark.decode_mark(blob, verify_pub=key.public_key())


def test_round_trip(key):
    m = _mark(key, server=True)
    assert m.high_water == HW and m.server_signed is True
    assert _mark(key, server=False).server_signed is False


def test_check_clock(key):
    m = _mark(key)
    clockmark.check_clock(m, HW)
    clockmark.check_clock(m, HW + 1)
    with pytest.raises(CoreVerifyError, match="clock_rolled_back"):
        clockmark.check_clock(m, HW - 1)


def test_advance_forward_and_never_back(key):
    m = _mark(key)
    fwd = clockmark.decode_mark(
        clockmark.advance(m, HW + 50, server_signed=False, sign_priv=key),
        verify_pub=key.public_key())
    assert fwd.high_water == HW + 50
    back = clockmark.decode_mark(
        clockmark.advance(m, HW - 50, server_signed=False, sign_priv=key),
        verify_pub=key.public_key())
    assert back.high_water == HW


@pytest.mark.parametrize("old,arg,delta,expected", [
    (False, True, 0, True),    # tie: server wins
    (True, False, 0, True),    # tie: server mark not downgraded
    (False, False, 0, False),
    (True, False, 10, False),  # strictly newer: src follows the new reading
    (False, True, 10, True),
    (True, True, -10, True),   # older reading: src unchanged
    (True, False, -10, True),
    (False, True, -10, False),
])
def test_advance_src(key, old, arg, delta, expected):
    m = _mark(key, server=old)
    out = clockmark.decode_mark(
        clockmark.advance(m, HW + delta, server_signed=arg, sign_priv=key),
        verify_pub=key.public_key())
    assert out.server_signed is expected


def test_flipped_byte_fails_verify(key):
    blob = clockmark.new_mark(HW, server_signed=True, sign_priv=key)
    d = json.loads(blob)
    d["hw"] += 1  # hand-edit the timestamp
    with pytest.raises(CoreVerifyError):
        clockmark.decode_mark(json.dumps(d).encode(), verify_pub=key.public_key())
    i = blob.index(b"sig") + 8
    bad = blob[:i] + bytes([blob[i] ^ 1]) + blob[i + 1:]
    with pytest.raises((CoreVerifyError, CoreFormatError)):
        clockmark.decode_mark(bad, verify_pub=key.public_key())


def test_wrong_pub_fails_verify(key):
    blob = clockmark.new_mark(HW, server_signed=True, sign_priv=key)
    with pytest.raises(CoreVerifyError):
        clockmark.decode_mark(blob, verify_pub=Ed25519PrivateKey.generate().public_key())


@pytest.mark.parametrize("blob", [
    b"", b"\xff\xfe", b"{not json", b"[]", b"{}",
    b'{"v":2,"hw":1,"src":"client","sig":"AA=="}',
    b'{"v":1,"hw":"1","src":"client","sig":"AA=="}',
    b'{"v":1,"hw":true,"src":"client","sig":"AA=="}',
    b'{"v":1,"hw":1,"src":"bogus","sig":"AA=="}',
    b'{"v":1,"hw":1,"src":"client","sig":"!!"}',
    b'{"v":1,"hw":1,"src":"client"}',
])
def test_malformed_is_format_error(key, blob):
    with pytest.raises(CoreFormatError):
        clockmark.decode_mark(blob, verify_pub=key.public_key())
