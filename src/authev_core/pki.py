"""Two-level X.509 CA (root -> intermediate -> short-lived leaf) with entitlements."""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.x509.oid import NameOID, ObjectIdentifier

from .errors import CoreVerifyError
from .primitives import canonical_json

ENTITLEMENT_OID = ObjectIdentifier("1.3.6.1.4.1.58888.1.1")
TPM_KEY_OID = ObjectIdentifier("1.3.6.1.4.1.58888.1.2")

_ROOT_DAYS = 3650


@dataclass(frozen=True)
class LeafInfo:
    user_id: str
    machine_id: str
    products: list[str]
    tpm_pub_der: bytes
    not_before: int
    not_after: int


def _dt(epoch: int) -> datetime:
    return datetime.fromtimestamp(epoch, tz=timezone.utc)


def _epoch(dt: datetime) -> int:
    return int(dt.replace(tzinfo=timezone.utc).timestamp())


def _name(cn: str, ou: str | None = None) -> x509.Name:
    attrs = [x509.NameAttribute(NameOID.COMMON_NAME, cn)]
    if ou is not None:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou))
    return x509.Name(attrs)


def new_root(now: int = 0, days: int = _ROOT_DAYS):
    """Self-signed root. Validity starts at the epoch unless `now` is given."""
    priv = Ed25519PrivateKey.generate()
    name = _name("authev-root")
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(priv.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_dt(now)).not_valid_after(_dt(now + days * 86400))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .sign(priv, None)
    )
    return priv, cert


def new_intermediate(root_priv, root_cert, now: int, days: int = 365):
    priv = Ed25519PrivateKey.generate()
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name("authev-intermediate")).issuer_name(root_cert.subject)
        .public_key(priv.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_dt(now)).not_valid_after(_dt(now + days * 86400))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(root_priv, None)
    )
    return priv, cert


def issue_leaf(inter_priv, inter_cert, *, user_id: str, machine_id: str,
               products: list[str], tpm_pub_der: bytes, now: int, days: int = 6):
    leaf_key = Ed25519PrivateKey.generate()
    return (
        x509.CertificateBuilder()
        .subject_name(_name(user_id, machine_id)).issuer_name(inter_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_dt(now)).not_valid_after(_dt(now + days * 86400))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.UnrecognizedExtension(
                ENTITLEMENT_OID, canonical_json({"products": list(products)})),
            critical=False)
        .add_extension(x509.UnrecognizedExtension(TPM_KEY_OID, tpm_pub_der), critical=False)
        .sign(inter_priv, None)
    )


def _check_signed_by(cert: x509.Certificate, issuer: x509.Certificate) -> None:
    pub = issuer.public_key()
    if not isinstance(pub, Ed25519PublicKey):
        raise CoreVerifyError("bad_chain")
    try:
        if cert.issuer != issuer.subject:
            raise CoreVerifyError("bad_chain")
        pub.verify(cert.signature, cert.tbs_certificate_bytes)
    except InvalidSignature:
        raise CoreVerifyError("bad_chain") from None


def verify_leaf(leaf: x509.Certificate, *, intermediate_cert: x509.Certificate,
                root_cert: x509.Certificate, now: int,
                product_id: str | None = None) -> LeafInfo:
    # Chain first: an unauthentic leaf must never be reported as merely expired.
    try:
        if intermediate_cert == root_cert:  # root must not stand in as its own intermediate
            raise CoreVerifyError("bad_chain")
        _check_signed_by(intermediate_cert, root_cert)
        _check_signed_by(leaf, intermediate_cert)
    except CoreVerifyError:
        raise
    except Exception:
        raise CoreVerifyError("bad_chain") from None

    nb = _epoch(leaf.not_valid_before_utc)
    na = _epoch(leaf.not_valid_after_utc)
    if now < nb:
        raise CoreVerifyError("not_yet_valid")
    if now > na:
        raise CoreVerifyError("expired")

    try:
        cn = leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        ou = leaf.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value
        ent = leaf.extensions.get_extension_for_oid(ENTITLEMENT_OID).value.value
        tpm = leaf.extensions.get_extension_for_oid(TPM_KEY_OID).value.value
        products = list(json.loads(ent)["products"])
    except Exception:
        raise CoreVerifyError("bad_chain") from None

    if product_id is not None and product_id not in products:
        raise CoreVerifyError("not_entitled")
    return LeafInfo(cn, ou, products, tpm, nb, na)
