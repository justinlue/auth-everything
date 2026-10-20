import pytest
from cryptography import x509

from authev_core import pki
from authev_core.errors import CoreVerifyError

NOW = 1_800_000_000
DAY = 86400
TPM = b"\x30\x82\x01\x22fake-tpm-rsa-pub-der"


@pytest.fixture(scope="module")
def chain():
    root_priv, root = pki.new_root()
    inter_priv, inter = pki.new_intermediate(root_priv, root, NOW)
    leaf = pki.issue_leaf(
        inter_priv, inter, user_id="user-1", machine_id="mach-1",
        products=["alpha", "beta"], tpm_pub_der=TPM, now=NOW,
    )
    return root_priv, root, inter_priv, inter, leaf


def verify(chain, **kw):
    _, root, _, inter, leaf = chain
    kw.setdefault("now", NOW + DAY)
    return pki.verify_leaf(leaf, intermediate_cert=inter, root_cert=root, **kw)


def test_oid():
    assert pki.ENTITLEMENT_OID.dotted_string == "1.3.6.1.4.1.58888.1.1"


def test_valid_leaf_returns_info(chain):
    info = verify(chain)
    assert info.user_id == "user-1"
    assert info.machine_id == "mach-1"
    assert info.products == ["alpha", "beta"]
    assert info.tpm_pub_der == TPM
    assert info.not_before == NOW
    assert info.not_after == NOW + 6 * DAY


def test_entitled_product_ok(chain):
    assert verify(chain, product_id="beta").products == ["alpha", "beta"]


def test_expired(chain):
    with pytest.raises(CoreVerifyError, match=r"^expired$"):
        verify(chain, now=NOW + 6 * DAY + 1)


def test_not_yet_valid(chain):
    with pytest.raises(CoreVerifyError, match=r"^not_yet_valid$"):
        verify(chain, now=NOW - 1)


def test_not_entitled(chain):
    with pytest.raises(CoreVerifyError, match=r"^not_entitled$"):
        verify(chain, product_id="gamma")


def test_wrong_root(chain):
    _, other_root = pki.new_root()
    _, _, _, inter, leaf = chain
    with pytest.raises(CoreVerifyError, match=r"^bad_chain$"):
        pki.verify_leaf(leaf, intermediate_cert=inter, root_cert=other_root, now=NOW + DAY)


def test_leaf_signed_directly_by_root(chain):
    root_priv, root, _, _, _ = chain
    leaf = pki.issue_leaf(
        root_priv, root, user_id="u", machine_id="m", products=["alpha"],
        tpm_pub_der=TPM, now=NOW,
    )
    with pytest.raises(CoreVerifyError, match=r"^bad_chain$"):
        pki.verify_leaf(leaf, intermediate_cert=root, root_cert=root, now=NOW + DAY)


def test_leaf_from_other_intermediate(chain):
    root_priv, root, _, inter, _ = chain
    other_priv, other_inter = pki.new_intermediate(root_priv, root, NOW)
    leaf = pki.issue_leaf(
        other_priv, other_inter, user_id="u", machine_id="m", products=["a"],
        tpm_pub_der=TPM, now=NOW,
    )
    with pytest.raises(CoreVerifyError, match=r"^bad_chain$"):
        pki.verify_leaf(leaf, intermediate_cert=inter, root_cert=root, now=NOW + DAY)


def test_bad_chain_beats_expiry_for_forged_leaf(chain):
    _, other_root = pki.new_root()
    _, _, _, inter, leaf = chain
    with pytest.raises(CoreVerifyError, match=r"^bad_chain$"):
        pki.verify_leaf(leaf, intermediate_cert=inter, root_cert=other_root, now=NOW + 99 * DAY)


def test_custom_days(chain):
    _, _, inter_priv, inter, _ = chain
    leaf = pki.issue_leaf(
        inter_priv, inter, user_id="u", machine_id="m", products=[],
        tpm_pub_der=TPM, now=NOW, days=2,
    )
    assert isinstance(leaf, x509.Certificate)
    with pytest.raises(CoreVerifyError, match=r"^expired$"):
        pki.verify_leaf(leaf, intermediate_cert=inter, root_cert=chain[1], now=NOW + 3 * DAY)
