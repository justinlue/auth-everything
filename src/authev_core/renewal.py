"""Renewal proof-of-possession payload.

The client signs a renewal request with its TPM RSA key (RSA-PSS, SHA-256);
the server verifies it against the TPM public key on record. The signer is
injected so this module stays pure.
"""

import base64
import binascii
import json
from collections.abc import Callable
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from authev_core.errors import CoreFormatError, CoreVerifyError
from authev_core.primitives import _load_rsa_public_key, canonical_json

Signer = Callable[[bytes], bytes]

_VERSION = 1


@dataclass(frozen=True)
class PopRequest:
    csr_der: bytes
    fingerprint: str
    nonce: bytes
    challenge: str
    ts: int
    sig: bytes


def _unsigned(csr_der: bytes, fingerprint: str, nonce: bytes, challenge: str, ts: int) -> dict:
    return {
        "v": _VERSION,
        "csr": base64.b64encode(csr_der).decode("ascii"),
        "fp": fingerprint,
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "challenge": challenge,
        "ts": ts,
    }


def _signed_bytes(req: PopRequest) -> bytes:
    return canonical_json(_unsigned(req.csr_der, req.fingerprint, req.nonce, req.challenge, req.ts))


def build_pop(*, csr_der: bytes, fingerprint: str, nonce: bytes, challenge: str,
              now: int, sign: Signer) -> bytes:
    body = _unsigned(csr_der, fingerprint, nonce, challenge, now)
    body["sig"] = base64.b64encode(sign(canonical_json(body))).decode("ascii")
    return canonical_json(body)


def _b64(d: dict, key: str) -> bytes:
    val = d[key]
    if not isinstance(val, str):
        raise CoreFormatError(f"{key} must be a string")
    try:
        return base64.b64decode(val.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError) as e:
        raise CoreFormatError(f"{key} is not valid base64") from e


def decode_pop(blob: bytes) -> PopRequest:
    try:
        d = json.loads(blob)
    except (ValueError, TypeError) as e:  # includes UnicodeDecodeError
        raise CoreFormatError("malformed pop payload") from e
    if not isinstance(d, dict):
        raise CoreFormatError("pop payload must be an object")
    v = d.get("v")
    if type(v) is not int or v != _VERSION:
        raise CoreFormatError("unsupported pop version")
    try:
        fp, challenge, ts = d["fp"], d["challenge"], d["ts"]
        csr, nonce, sig = _b64(d, "csr"), _b64(d, "nonce"), _b64(d, "sig")
    except KeyError as e:
        raise CoreFormatError(f"missing field {e.args[0]}") from e
    if not isinstance(fp, str) or not isinstance(challenge, str):
        raise CoreFormatError("fp and challenge must be strings")
    if type(ts) is not int:
        raise CoreFormatError("ts must be an integer")
    return PopRequest(csr_der=csr, fingerprint=fp, nonce=nonce,
                      challenge=challenge, ts=ts, sig=sig)


def verify_pop(blob: bytes, *, tpm_pub_der: bytes, expect_challenge: str,
               max_age_s: int, now: int) -> PopRequest:
    """Check order: format, signature, challenge, freshness.

    Authenticity is established before any claimed field is acted on.
    """
    req = decode_pop(blob)
    pub = _load_rsa_public_key(tpm_pub_der)
    try:
        pub.verify(
            req.sig, _signed_bytes(req),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.DIGEST_LENGTH),
            hashes.SHA256(),
        )
    except InvalidSignature:
        raise CoreVerifyError("bad_sig") from None
    if req.challenge != expect_challenge:
        raise CoreVerifyError("bad_challenge")
    if now - req.ts > max_age_s:
        raise CoreVerifyError("stale")
    return req
