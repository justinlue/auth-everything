"""TPM-wrapped asset-key envelope.

The server RSA-OAEP(SHA-256)-encrypts the per-product asset key K_p to a
machine's TPM public key. The client unwraps it through an injected
callable (the TPM decrypt), only after its other checks pass.
"""

import base64
import binascii
import json
from collections.abc import Callable

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from authev_core.errors import CoreFormatError, CoreVerifyError
from authev_core.primitives import canonical_json

_VERSION = 1

Unwrapper = Callable[[bytes], bytes]


def _oaep() -> padding.OAEP:
    return padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


def wrap(*, k_p: bytes, product_id: str, version: str, not_after: int,
         tpm_pub_der: bytes) -> bytes:
    try:
        pub = serialization.load_der_public_key(tpm_pub_der)
    except (ValueError, UnsupportedAlgorithm) as e:
        raise CoreFormatError("invalid TPM public key") from e
    if not isinstance(pub, rsa.RSAPublicKey):
        raise CoreFormatError("TPM public key must be RSA")
    wk = base64.b64encode(pub.encrypt(k_p, _oaep())).decode("ascii")
    return canonical_json({"v": _VERSION, "pid": product_id, "ver": version,
                           "exp": not_after, "wk": wk})


def _decode(blob: bytes) -> tuple[str, int, bytes]:
    try:
        d = json.loads(blob)
    except (ValueError, TypeError) as e:  # includes UnicodeDecodeError
        raise CoreFormatError("malformed asset-key envelope") from e
    if not isinstance(d, dict):
        raise CoreFormatError("asset-key envelope must be an object")
    v = d.get("v")
    if type(v) is not int or v != _VERSION:
        raise CoreFormatError("unsupported asset-key envelope version")
    try:
        pid, ver, exp, wk = d["pid"], d["ver"], d["exp"], d["wk"]
    except KeyError as e:
        raise CoreFormatError(f"missing field {e.args[0]}") from e
    if not isinstance(pid, str) or not isinstance(ver, str):
        raise CoreFormatError("pid and ver must be strings")
    if type(exp) is not int:
        raise CoreFormatError("exp must be an integer")
    if not isinstance(wk, str):
        raise CoreFormatError("wk must be a string")
    try:
        ct = base64.b64decode(wk, validate=True)
    except (binascii.Error, ValueError) as e:
        raise CoreFormatError("wk is not valid base64") from e
    return pid, exp, ct


def unwrap(blob: bytes, *, product_id: str, now: int, unwrap: Unwrapper) -> bytes:
    """Return K_p by passing the wrapped key to the injected TPM unwrapper.

    SECURITY NOTE: pid, ver and exp are plaintext and NOT integrity-protected;
    anyone who can edit the stored blob can rewrite them and the TPM will still
    decrypt wk. The "wrong_product" and "expired" checks here are advisory
    routing checks, NOT a security boundary. The binding entitlement and expiry
    MUST be enforced upstream (leaf certificate and clock mark) before unwrap
    is ever called. The only cryptographic guarantee of this envelope is that
    K_p is recoverable solely by the holder of the matching TPM private key.
    Callers must not treat these two checks as enforcement.
    """
    # Order: product match first (a blob for another product is the more
    # fundamental error), then expiry; the TPM is touched only after both pass.
    pid, exp, ct = _decode(blob)
    if pid != product_id:
        raise CoreVerifyError("wrong_product")
    if now > exp:
        raise CoreVerifyError("expired")
    return unwrap(ct)
