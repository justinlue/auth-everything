"""Signed clock high-water mark (anti clock-rollback).

The mark records the latest time ever seen. It is signed (Ed25519) so it
cannot be hand-edited, but not encrypted: a timestamp is not secret.
"""

import base64
import binascii
import json
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from authev_core.errors import CoreFormatError, CoreVerifyError
from authev_core.primitives import canonical_json, ed25519_sign, ed25519_verify

_VERSION = 1
_SRC_SERVER = "server"
_SRC_CLIENT = "client"


@dataclass(frozen=True)
class ClockMark:
    high_water: int
    server_signed: bool


def _unsigned(high_water: int, server_signed: bool) -> dict:
    return {"v": _VERSION, "hw": high_water,
            "src": _SRC_SERVER if server_signed else _SRC_CLIENT}


def new_mark(high_water: int, *, server_signed: bool, sign_priv: Ed25519PrivateKey) -> bytes:
    body = _unsigned(high_water, server_signed)
    body["sig"] = base64.b64encode(ed25519_sign(sign_priv, canonical_json(body))).decode("ascii")
    return canonical_json(body)


def decode_mark(blob: bytes, *, verify_pub: Ed25519PublicKey) -> ClockMark:
    try:
        d = json.loads(blob)
    except (ValueError, TypeError) as e:  # includes UnicodeDecodeError
        raise CoreFormatError("malformed clock mark") from e
    if not isinstance(d, dict):
        raise CoreFormatError("clock mark must be an object")
    v = d.get("v")
    if type(v) is not int or v != _VERSION:
        raise CoreFormatError("unsupported clock mark version")
    try:
        hw, src, sig_b64 = d["hw"], d["src"], d["sig"]
    except KeyError as e:
        raise CoreFormatError(f"missing field {e.args[0]}") from e
    if type(hw) is not int:
        raise CoreFormatError("hw must be an integer")
    if src not in (_SRC_SERVER, _SRC_CLIENT):
        raise CoreFormatError("invalid src")
    if not isinstance(sig_b64, str):
        raise CoreFormatError("sig must be a string")
    try:
        sig = base64.b64decode(sig_b64.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError) as e:
        raise CoreFormatError("sig is not valid base64") from e
    server_signed = src == _SRC_SERVER
    ed25519_verify(verify_pub, canonical_json(_unsigned(hw, server_signed)), sig)
    return ClockMark(high_water=hw, server_signed=server_signed)


def check_clock(mark: ClockMark, now: int) -> None:
    if now < mark.high_water:
        raise CoreVerifyError("clock_rolled_back")


def advance(mark: ClockMark, now: int, *, server_signed: bool,
            sign_priv: Ed25519PrivateKey) -> bytes:
    """Return a new signed mark; high_water never decreases.

    src: now > hw -> the new reading's source; now == hw -> server wins the
    tie (mark or argument); now < hw -> hw and src are kept unchanged.
    """
    if now > mark.high_water:
        src_server = server_signed
    elif now == mark.high_water:
        src_server = mark.server_signed or server_signed
    else:
        src_server = mark.server_signed
    return new_mark(max(mark.high_water, now), server_signed=src_server, sign_priv=sign_priv)
