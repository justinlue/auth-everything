# auth-everything — Design Spec (v1)

**Status:** confirmed 2026-10-20. v1 target: **Windows only**. Language: **Python 3.14** throughout, client/packer/launcher distributed as Nuitka onefile executables.

## 1. Purpose & threat model

A licensing gate. A protected program runs only after a valid, unexpired
certificate is verified **locally**. Certificates last **6 days** and
auto-renew; when the issuer stops renewing a user's machine, that machine
can no longer run protected programs within 6 days. Works offline between
renewals.

The licensee is the adversary: they hold the files, the machine, and (if
configured) the passphrase. The gate raises the cost of unauthorized use;
it is not unbreakable. Defences: compiled binaries (Nuitka), encrypted
assets, TPM-bound keys, and a signed clock high-water mark.

## 2. Certificates & CA

- **X.509, Ed25519.** Leaf certificate validity: **6 days**.
- **Two-level CA.** An offline **root** key (USB / issuer PC) signs an
  **issuing intermediate** (validity: **1 year**) held on the server.
  Clients ship the **root** public key as their trust anchor. A server
  compromise is recovered by rotating the intermediate.
- **Leaf subject** carries a **user ID** and a **machine ID**.
- **Entitlements:** a custom certificate extension (OID under a private
  arc) carries a list of **product IDs** the holder may run. Each protected
  program declares its product ID and is refused unless it is listed.
- One certificate per **user per machine**.

## 3. Machine binding

- Leaf private key is generated **in the TPM** via the Windows Platform
  Crypto Provider (CNG/NCrypt), **non-exportable**. Key type RSA-2048
  (TPM-backed; used for signing the proof-of-possession and for unwrapping
  asset keys).
- A **hardware fingerprint** (board serial, disk serial, machine GUID) is
  embedded in the certificate (machine ID is derived from it) and
  re-checked at every launch as a secondary binding.
- **No passphrase** by default; an optional per-user passphrase can wrap
  local state for shared-PC cases.

## 4. Clock-tamper defence

- A signed, encrypted **"latest time ever seen"** high-water mark is kept
  in local state. If the system clock reads earlier than the mark, the gate
  refuses to run. The mark's signature is verified against the CA key so it
  cannot be hand-edited.
- Every renewal response carries **signed server time**, which becomes a
  trusted anchor and advances the mark.

## 5. Online = renewal only

- Every login verifies **locally** against the CA trust anchor — online and
  offline logins share one code path.
- **Auto-renew** triggers when **< 3 days** remain.
- Renewal is **proof-of-possession over HTTPS** (no mTLS): the client sends
  `{csr, fingerprint, nonce, server-issued challenge, timestamp}` signed by
  its TPM key; the server verifies the signature against the certificate on
  record. Proxy/CDN friendly.
- After expiry: a **7-day renewal grace window** during which renewal still
  works, but **the protected program refuses to run the instant the leaf
  expires**. After the grace window, re-enrollment is required.

## 6. Attaching to a program

Two paths:

- **Library** (stronger): the app calls `auth_everything.require(product_id)`
  at startup and receives the product's asset key. No fully decrypted copy
  of the program is written to disk.
- **Packer** (convenience, any program): `authev pack <program> ...` seals a
  program into an encrypted bundle. The launcher verifies the gate, then
  decrypts the program into a **per-run temp folder** whose ACL grants the
  current user only, runs it as a child process, and deletes the folder on
  exit (and sweeps leftovers from crashed prior runs at startup).
  **Trade-off (documented):** the decrypted program exists on disk while it
  runs and could be copied by someone with access to that account. Launcher
  and bundles are **Authenticode-signed**.

v1 demo: a small Nuitka-built EXE that uses the library **and** is packed.

## 7. Asset keys

- Each product has an asset key **`K_p`** (symmetric, AES-256-GCM) used to
  encrypt that product's assets/bundle.
- At enrollment and each renewal the server delivers `K_p` **wrapped to this
  machine's TPM key** (RSA-OAEP to the TPM public key), with an expiry
  matching the leaf. The gate unwraps `K_p` via the TPM only after the leaf,
  clock mark, and entitlement all pass.
- `K_p` is **rotated per product version** to limit exposure from any leak.

## 8. Enrollment

- One-time token. Admin runs `authev-admin invite <user> --product <id>`,
  producing a token valid **48 h**. The user runs `authev enroll <token>`:
  the TPM generates the key, the client sends CSR + fingerprint, the server
  auto-issues because the token pre-approved it.
- The same token flow handles **re-enrollment** after the grace window.

## 9. Server

- **Python (FastAPI) + SQLite**, in Docker on a VPS behind Caddy.
- Responsibilities: enroll / issue / renew, user+machine database, signed
  time. Holds the issuing **intermediate** key only (root stays offline).

## 10. Client packaging & UX

- **Python 3.14**, distributed as **Nuitka onefile** executables: `authev`
  (CLI), the launcher, `authev-admin`. The `auth_everything` library is a
  normal pip-installable package for the library path.
- **Silent** login on launch; auto-renews under 3 days. No prompt unless
  something fails.
- `authev status` — days left, last renewal. `authev diagnose` — leaf
  validity, days left, clock-mark state, TPM availability, server
  reachability.
- Distinct plain-language failure messages **with error codes** for:
  expired-offline, clock-rolled-back, wrong-machine, missing-entitlement,
  revoked.
- Local state under `%LOCALAPPDATA%\authev\`: leaf cert, TPM key handle
  reference, wrapped asset keys, signed clock mark. Optional daily scheduled
  task for background renewal.

## 11. Subsystems & shared contracts

Built as five subsystems, each with its own implementation plan:

1. **`authev-core`** — Python package of crypto + wire formats shared by
   client and server: certificate profile (entitlement extension), signed
   clock-mark, renewal proof-of-possession payload, TPM-wrapped asset-key
   envelope. Pure, host-testable, no TPM or network.
2. **CA server** — FastAPI + SQLite; enroll/issue/renew/signed-time; two-level CA.
3. **Client core** — NCrypt TPM key, local verification, clock-mark
   enforcement, enroll/renew, `authev` CLI.
4. **Packer + launcher** — seal/run, Authenticode signing.
5. **Python library + demo EXE** — `auth_everything.require()` + demo.

Dependency order: core → {server, client} → {packer, library+demo}.

## 12. Global constraints

- Python **3.14**; standard library + `cryptography`, `argon2-cffi`
  (passphrase KDF), `fastapi`/`uvicorn` (server), `nuitka` (build). No other
  heavy dependencies without reason.
- Crypto: signatures **Ed25519**; symmetric **AES-256-GCM**; asset-key wrap
  **RSA-OAEP (SHA-256)** to the TPM key; passphrase KDF **Argon2id**.
- All wire payloads are versioned (a leading format-version field) so client
  and server can evolve independently.
- Times are UTC, serialized as RFC 3339 / epoch seconds; never trust local
  time for validity without the clock mark.
