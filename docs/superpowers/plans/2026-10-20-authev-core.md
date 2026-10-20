# authev-core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `authev-core`, the pure-Python package of crypto primitives and versioned wire formats that the CA server and the client both encode/decode against.

**Architecture:** One installable package `authev_core` with focused modules: a two-level Ed25519 CA and X.509 leaf profile (with a custom entitlement extension), a signed/encrypted clock-mark, a signed renewal proof-of-possession payload, and a TPM-wrapped asset-key envelope. Everything here is deterministic and host-testable: no TPM calls and no network. The TPM is modeled as an injected key-op interface so core stays pure and the client supplies the real NCrypt implementation later.

**Tech Stack:** Python 3.14, `cryptography`, `argon2-cffi`; `pytest` for tests; `pyproject.toml` (PEP 621) build.

**Spec:** `docs/DESIGN.md`

## Global Constraints

- Python **3.14**. Dependencies limited to `cryptography`, `argon2-cffi` (runtime) and `pytest` (dev).
- Signatures **Ed25519**; symmetric **AES-256-GCM** (96-bit nonce, 256-bit key); asset-key wrap **RSA-OAEP(SHA-256)**; passphrase KDF **Argon2id**.
- Every wire payload begins with an integer `v` format-version field; v1 payloads use `v == 1`.
- All times are UTC epoch seconds (integers). Core never reads the system clock to decide validity — callers pass the time in.
- Entitlement extension OID: `1.3.6.1.4.1.58888.1.1` (private arc placeholder; fixed for v1). Leaf validity 6 days, intermediate 1 year are produced by core but callers pass `not_before`/`now`.

## Review Focus

- **Expired / not-yet-valid leaf:** `verify_leaf` must reject a leaf whose `[not_before, not_after]` does not contain the supplied `now`, with a distinct reason, not a generic failure. (Task 2)
- **Clock rollback:** `check_clock_mark` must reject when `now < mark.high_water`, and `advance_clock_mark` must never move the mark backward. (Task 4)
- **Tampered signed payloads:** a clock mark, PoP payload, or asset envelope whose bytes were altered after signing must fail verification rather than decode to attacker-chosen values. (Tasks 4, 5, 6)
- **Wrong trust anchor / broken chain:** `verify_leaf` must reject a leaf whose intermediate is not signed by the pinned root, and reject a leaf signed directly by the root. (Task 2)
- **Unknown/garbage input & version skew:** every `decode_*` must raise a typed `CoreFormatError` on truncated bytes, wrong type, or a `v` it does not support — never return a partial object. (Tasks 3–6)

---

### Task 1: Package skeleton, errors, and primitives

**Files:**
- Create: `pyproject.toml`
- Create: `src/authev_core/__init__.py`
- Create: `src/authev_core/errors.py`
- Create: `src/authev_core/primitives.py`
- Test: `tests/test_primitives.py`

**Interfaces:**
- Produces:
  - `errors.CoreError` (base), `errors.CoreFormatError(CoreError)`, `errors.CoreVerifyError(CoreError)`.
  - `primitives.aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes` returning `nonce(12) || ciphertext||tag`; `primitives.aes_gcm_decrypt(key: bytes, blob: bytes, aad: bytes = b"") -> bytes`.
  - `primitives.ed25519_sign(priv: Ed25519PrivateKey, msg: bytes) -> bytes`; `primitives.ed25519_verify(pub: Ed25519PublicKey, msg: bytes, sig: bytes) -> None` (raises `CoreVerifyError`).
  - `primitives.derive_key_argon2id(passphrase: str, salt: bytes) -> bytes` (32 bytes).
  - `primitives.canonical_json(obj: dict) -> bytes` (sorted keys, no whitespace, UTF-8) — the signing serialization used by all signed payloads.

- [ ] **Step 1: Write failing tests** in `tests/test_primitives.py`: AES-GCM round-trips and fails on altered ciphertext (`CoreVerifyError`/`InvalidTag`→wrapped); AES-GCM decrypt with wrong `aad` fails; Ed25519 sign/verify round-trip and verify raises `CoreVerifyError` on a flipped bit; `canonical_json({"b":1,"a":2}) == b'{"a":2,"b":1}'`; `derive_key_argon2id` is deterministic for same salt and differs for different salt.
- [ ] **Step 2: Run tests, verify they fail** — Run: `pytest tests/test_primitives.py -v`. Expected: FAIL (module not found / names undefined).
- [ ] **Step 3: Implement** `errors.py`, `primitives.py`, and `pyproject.toml` (PEP 621, `src/` layout, deps `cryptography`, `argon2-cffi`). Argon2id via `argon2.low_level.hash_secret_raw` with fixed sane params (recorded as module constants); wrap `cryptography` `InvalidTag` into `CoreVerifyError`.
- [ ] **Step 4: Run tests, verify pass** — Run: `pytest tests/test_primitives.py -v`. Expected: PASS.
- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(core): package skeleton, errors, crypto primitives"`.

---

### Task 2: Two-level CA and leaf certificate profile

**Files:**
- Create: `src/authev_core/pki.py`
- Test: `tests/test_pki.py`

**Interfaces:**
- Consumes: Task 1 primitives/errors.
- Produces:
  - `pki.ENTITLEMENT_OID` (= `1.3.6.1.4.1.58888.1.1`).
  - `pki.new_root() -> (Ed25519PrivateKey, x509.Certificate)` — self-signed root.
  - `pki.new_intermediate(root_priv, root_cert, now: int, days: int = 365) -> (Ed25519PrivateKey, x509.Certificate)`.
  - `pki.issue_leaf(inter_priv, inter_cert, *, user_id: str, machine_id: str, products: list[str], tpm_pub_der: bytes, now: int, days: int = 6) -> x509.Certificate` — embeds subject user/machine IDs, the entitlement extension (JSON list of product IDs), and `tpm_pub_der` (the machine's TPM RSA public key, so the leaf binds to it).
  - `pki.verify_leaf(leaf: x509.Certificate, *, intermediate_cert: x509.Certificate, root_cert: x509.Certificate, now: int, product_id: str | None = None) -> LeafInfo` — the caller supplies the full chain (core keeps no store). Verifies that `intermediate_cert` is signed by `root_cert` and `leaf` by `intermediate_cert`, that `now` falls in the leaf's `[not_before, not_after]`, and (if `product_id` given) that it is entitled. Raises `CoreVerifyError` with distinct messages: `"expired"`, `"not_yet_valid"`, `"bad_chain"`, `"not_entitled"`. Returns `LeafInfo(user_id, machine_id, products, tpm_pub_der, not_before, not_after)`.

- [ ] **Step 1: Write failing tests** in `tests/test_pki.py`: build root→intermediate→leaf; `verify_leaf` returns `LeafInfo` with the exact `user_id`/`machine_id`/`products`/`tpm_pub_der`; rejects with `"expired"` when `now > not_after`; `"not_yet_valid"` when `now < not_before`; `"not_entitled"` when asking for a product not in the list; `"bad_chain"` when the leaf is verified against a *different* root, and when a leaf signed directly by the root is passed as its own intermediate.
- [ ] **Step 2: Run tests, verify they fail** — Run: `pytest tests/test_pki.py -v`. Expected: FAIL.
- [ ] **Step 3: Implement** `pki.py` using `cryptography.x509` builders with Ed25519 issuers. Entitlement extension stored as an `UnrecognizedExtension` carrying `canonical_json({"products": [...]})` under `ENTITLEMENT_OID`. Chain verification: check intermediate is signed by root and leaf by intermediate via `public_key().verify(...)` on `tbs_certificate_bytes`; map failures to `"bad_chain"`.
- [ ] **Step 4: Run tests, verify pass** — Run: `pytest tests/test_pki.py -v`. Expected: PASS.
- [ ] **Step 5: Commit** — `git commit -am "feat(core): two-level CA and leaf profile with entitlement extension"`.

---

### Task 3: Renewal proof-of-possession payload

**Files:**
- Create: `src/authev_core/renewal.py`
- Test: `tests/test_renewal.py`

**Interfaces:**
- Consumes: Tasks 1–2; an injected signer callable `Signer = Callable[[bytes], bytes]` (the client supplies the TPM RSA-PSS signer; tests supply a software one) and a verifier `verify_pop(pub_der, payload)`.
- Produces:
  - `renewal.build_pop(*, csr_der: bytes, fingerprint: str, nonce: bytes, challenge: str, now: int, sign: Signer) -> bytes` — returns `canonical_json` of `{v:1, csr, fp, nonce, challenge, ts, sig}` where `sig` is base64 of `sign(signed_bytes)` and `signed_bytes = canonical_json` of the same dict without `sig`.
  - `renewal.decode_pop(blob: bytes) -> PopRequest` — raises `CoreFormatError` on bad/truncated/`v!=1`.
  - `renewal.verify_pop(blob: bytes, *, tpm_pub_der: bytes, expect_challenge: str, max_age_s: int, now: int) -> PopRequest` — verifies RSA-PSS(SHA-256) signature over `signed_bytes` with the TPM public key, matches `challenge`, and rejects `now - ts > max_age_s`; distinct `CoreVerifyError` messages `"bad_sig"`, `"bad_challenge"`, `"stale"`.

- [ ] **Step 1: Write failing tests**: round-trip build→verify with a software RSA key as stand-in TPM key; altering any field after signing yields `"bad_sig"`; wrong `expect_challenge` → `"bad_challenge"`; `now` beyond `max_age_s` → `"stale"`; truncated bytes / `v:2` → `CoreFormatError`.
- [ ] **Step 2: Run tests, verify they fail** — `pytest tests/test_renewal.py -v`. Expected: FAIL.
- [ ] **Step 3: Implement** `renewal.py`; RSA-PSS via `cryptography`, base64 for `sig`/`nonce`/`csr`.
- [ ] **Step 4: Run tests, verify pass** — `pytest tests/test_renewal.py -v`. Expected: PASS.
- [ ] **Step 5: Commit** — `git commit -am "feat(core): renewal proof-of-possession payload"`.

---

### Task 4: Signed clock-mark

**Files:**
- Create: `src/authev_core/clockmark.py`
- Test: `tests/test_clockmark.py`

**Interfaces:**
- Consumes: Tasks 1–2.
- Produces:
  - `clockmark.new_mark(high_water: int, *, server_signed: bool, sign_priv: Ed25519PrivateKey) -> bytes` — `aes_gcm_encrypt` is **not** used here (the mark is integrity-protected, not secret); emit `canonical_json({v:1, hw, src})` plus an Ed25519 `sig` field, signed by the CA key.
  - `clockmark.decode_mark(blob: bytes, *, verify_pub: Ed25519PublicKey) -> ClockMark` — verifies signature; raises `CoreFormatError`/`CoreVerifyError`.
  - `clockmark.check_clock(mark: ClockMark, now: int) -> None` — raises `CoreVerifyError("clock_rolled_back")` when `now < mark.high_water`.
  - `clockmark.advance(mark: ClockMark, now: int, *, server_signed: bool, sign_priv) -> bytes` — returns a new signed mark with `high_water = max(mark.high_water, now)`; never decreases; `server_signed` source wins ties.

- [ ] **Step 1: Write failing tests**: round-trip new→decode; `check_clock` passes when `now >= hw` and raises `"clock_rolled_back"` when earlier; `advance` with a larger `now` moves hw forward and with a smaller `now` keeps it; a flipped byte in the blob → `CoreVerifyError`; decode with wrong `verify_pub` → `CoreVerifyError`.
- [ ] **Step 2: Run tests, verify they fail** — `pytest tests/test_clockmark.py -v`. Expected: FAIL.
- [ ] **Step 3: Implement** `clockmark.py`.
- [ ] **Step 4: Run tests, verify pass** — `pytest tests/test_clockmark.py -v`. Expected: PASS.
- [ ] **Step 5: Commit** — `git commit -am "feat(core): signed clock high-water mark"`.

---

### Task 5: TPM-wrapped asset-key envelope

**Files:**
- Create: `src/authev_core/assetkey.py`
- Test: `tests/test_assetkey.py`

**Interfaces:**
- Consumes: Tasks 1–2; an injected unwrap callable `Unwrapper = Callable[[bytes], bytes]` (client supplies the TPM NCryptDecrypt; tests supply software RSA-OAEP decrypt).
- Produces:
  - `assetkey.wrap(*, k_p: bytes, product_id: str, version: str, not_after: int, tpm_pub_der: bytes) -> bytes` — RSA-OAEP(SHA-256) encrypt `k_p` to the TPM public key, wrap as `canonical_json({v:1, pid, ver, exp, wk})` where `wk` is base64 of the OAEP ciphertext.
  - `assetkey.unwrap(blob: bytes, *, product_id: str, now: int, unwrap: Unwrapper) -> bytes` — decode, check `pid == product_id` (`"wrong_product"`) and `now <= exp` (`"expired"`), then return `unwrap(wk)` (the 32-byte `k_p`). `CoreFormatError` on bad bytes.

- [ ] **Step 1: Write failing tests**: with a software RSA keypair as stand-in TPM, `wrap` then `unwrap` returns the original `k_p`; mismatched `product_id` → `"wrong_product"`; `now > exp` → `"expired"`; truncated/`v:2` → `CoreFormatError`; altered `wk` makes the injected unwrap raise (propagated).
- [ ] **Step 2: Run tests, verify they fail** — `pytest tests/test_assetkey.py -v`. Expected: FAIL.
- [ ] **Step 3: Implement** `assetkey.py`.
- [ ] **Step 4: Run tests, verify pass** — `pytest tests/test_assetkey.py -v`. Expected: PASS.
- [ ] **Step 5: Commit** — `git commit -am "feat(core): TPM-wrapped asset-key envelope"`.

---

### Task 6: Public API surface and version guard

**Files:**
- Modify: `src/authev_core/__init__.py`
- Create: `tests/test_api.py`

**Interfaces:**
- Produces: `authev_core.__version__` and re-exports of the public names from Tasks 1–5, plus `authev_core.FORMAT_VERSION = 1`.

- [ ] **Step 1: Write failing tests** in `tests/test_api.py`: `from authev_core import verify_leaf, build_pop, verify_pop, new_mark, check_clock, wrap, unwrap, CoreFormatError, CoreVerifyError, FORMAT_VERSION` all import; `FORMAT_VERSION == 1`; a one-line "cross-module" test that feeds each `decode_*` a `{"v":2,...}` payload and asserts `CoreFormatError`.
- [ ] **Step 2: Run tests, verify they fail** — `pytest tests/test_api.py -v`. Expected: FAIL (names not exported).
- [ ] **Step 3: Implement** the re-exports in `__init__.py`.
- [ ] **Step 4: Run full suite** — Run: `pytest -q`. Expected: all green.
- [ ] **Step 5: Commit** — `git commit -am "feat(core): public API surface and version guard"`.
