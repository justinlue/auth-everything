# Carry-forward items for the server & client plans

These are real, reviewer-confirmed items deliberately deferred out of
`authev-core` (the pure crypto/format library). They are **not** core defects
— core's job is formats + local verification — but the subsystems that build
on it MUST handle them, or the product's security guarantees don't hold.
Source: whole-branch review of `authev-core` (2026-10-20).

## CA server plan (plan 2) — MUST enforce

- **Issuer validity windows.** `pki.verify_leaf` does NOT check the
  intermediate's or root's own `[not_before, not_after]` against `now`. The
  server (and client verification) must reject a chain whose intermediate or
  root is outside its validity window — otherwise an expired intermediate
  still validates leaves.
- **`new_root` default date trap.** `pki.new_root(now=0, ...)` yields a
  1970–1980 validity window. The moment issuer-validity checking is added,
  any chain built with the default `new_root()` breaks. Always pass a real
  `now`; a comment flags this at `new_root`.
- **CA BasicConstraints.** Set on issue but not enforced on verify. Low
  impact today (leaves never hold a signing key), but path validation on the
  server should enforce `ca=True`/pathlen on the intermediate.
- **Renewal freshness lower bound.** `renewal.verify_pop` accepts a *future*
  `ts` (no lower skew bound). The server must reject `ts - now > skew` as
  stale/clock-skew, in addition to core's upper-bound `now - ts > max_age`.
- **Asset-envelope authentication (optional).** `assetkey` envelope metadata
  (`pid`/`ver`/`exp`) is intentionally unauthenticated and documented as
  advisory. Enforcement of entitlement/expiry lives in the leaf cert + clock
  mark. If the envelope's own fields ever need to be trust-bearing, have the
  CA sign the envelope metadata server-side (additive signed field; does not
  break the current `unwrap` format).

## Client plan (plan 3) — MUST match

- **TPM RSA-PSS salt length.** The real NCrypt/TPM signer MUST use salt
  length == digest length (SHA-256), matching what `renewal.verify_pop`
  expects. A mismatch makes every renewal signature fail verification.
- **`tpm_pub_der` load-error semantics.** Core maps a bad/unsupported key to
  `CoreFormatError` ("invalid RSA public key"). Revisit whether that's the
  right surface when wiring NCrypt (the key is server-trusted data, not raw
  client input).
- **Enforcement order.** Entitlement and expiry are enforced by the leaf
  cert + clock mark, which gate whether `assetkey.unwrap` is ever called.
  Never treat `unwrap`'s `"wrong_product"`/`"expired"` as the enforcement
  point (see the docstring on `unwrap`).

## Polish (nice-to-have, any plan)

- `pki` broad `except Exception -> "bad_chain"` mislabels a parse failure on
  an otherwise-authentic cert; a dedicated message would be clearer.
- `clockmark.new_mark` accepts negative/bool `hw` (server-controlled input);
  add validation + an explicit `src`-only-tamper test.
- Replace the magic `16` (GCM tag length) in `primitives.py` with a named
  constant.
- Minor test-style nits (Tasks 1, 3, 4, 6): a few assertions could be
  parametrized / use exact-message anchors.
