# Conduit sealed messages — opt-in candidate, live release disabled

This is a runnable local implementation, not an approved independent-custody deployment.
Aaron selected **keep live release disabled until independent guardians are selected**.
All production guardian admission paths refuse; changing `assurance` to `reviewed`
does not unlock them. Existing messaging, live keys and billing are untouched.

## What it does

- Encrypt all message content, or keep an optional public note and encrypt the rest.
- Deliver ciphertext first and retain a separate **recipient-encrypted capsule** for later
  publication over a separately chosen channel. Never send a bare decryption key.
- Exercise a 2-of-3 guardian release with distinct encryption, signing and approval keys.
  Guardians release shares re-encrypted for the recipient; the recipient's own key is
  also necessary. Each approval binds the guardian, recipient-signed request, message,
  policy and expiry. One shared approval does not count three times.
- Prepare ciphertext fulfillment durably before one exact **2-DD surcharge**, reconcile
  ambiguous payment by the same idempotency key, and return only after durable payment.
  Normal transport/read/ack fees remain separate. Direct encryption has no release fee.
- Preserve ciphertext history through the existing Conduit log and receipt paths.
  Relay forwarding/broadcast is refused; re-encrypt for a different recipient.

## Endpoint use

Requires Node >=20 and Linux for the fixture process runner. HPKE/AES-GCM use fresh
message keys; dependencies are pinned in `package-lock.json`. Ordinary SDK functions
do not load the new crypto modules. Encryption is not automatically enabled by onboarding.

Set `DEMIPASS_SEALED_ENABLE=1` only on an endpoint you intend to opt in. The MCP tools are:

1. `conduit_sealed_identity`: create once or read the mailbox's existing key. Returns
   **public** keys/fingerprint only. Exchange and pin them through an authenticated
   channel; a relay directory, address claim or message-supplied key is insufficient.
2. `conduit_sealed_prepare`: supply pinned recipient public key, plaintext, optional
   `public_text`, and `defer_capsule` (default `true`). This creates a durable outbox
   entry; it neither sends nor charges. Content limit: 24 KiB UTF-8, public note: 1 KiB.
3. `conduit_sealed_send`: submit the prepared ID. It refuses a relay without the new
   sealed-transport capability. Retries retain the same ID and exact bytes.
4. `conduit_sealed_capsule`: obtain the separately stored encrypted capsule for later
   publication. The tool does not send it or choose a second service on your behalf.
5. `conduit_sealed_open`: supply envelope, capsule and independently pinned sender key.
   Authentication or missing-key failures hold. Plaintext is returned to the endpoint.

Keys and encrypted outbox files are private (0600 inside 0700 directories) under
`~/.local/state/demipass/sealed`, overridable with `DEMIPASS_SEALED_DIRECTORY`.
Initialization never silently replaces an existing key. Back up this directory securely
before relying on it for history: losing a private key can make history unrecoverable.
Same-UID processes and the host administrator can read these local keys. This is not
isolation between panes on one computer. Never copy keys into prompts, Git or receipts.

The low-level SDK modules support fixture guarded capsules and explicit guardian
release evidence. MCP deliberately has no live guardian-enrollment/approval bypass.
Model-visible plaintext passed to or returned by these tools remains visible to that
model provider; E2EE protects transport/storage boundaries, not the authorized endpoint.

## Separate guardian/coordinator processes

`sealed/service.sh PRIVATE_INSTANCE_DIRECTORY` starts one fixture-only Linux process
under a held `flock`. The directory must be owned by the current UID and mode 0700;
`config.json` must be mode 0600. Do not run `service.js` directly. Another process
cannot acquire the same instance lease; process death releases it. Journals append
hash-chained ciphertext/public evidence and fsync before successful responses. Replay
re-fsyncs recovered bytes. Partial/corrupt state holds for reconciliation, not truncation.

Each guardian config has:

```text
fixture: true
role: "guardian"
id: the guardian's policy id
identity: its private fixture keypair (never shared with the coordinator)
policy: exact pinned 2-of-3 fixture policy
sender / recipient: pinned public key records
transport_token: distinct random private service credential
port: 0 or a chosen loopback port
```

The coordinator uses `role: "coordinator"`, the same public pins/policy, its own
transport token, `guardian_endpoints: {id: {url,token}}`, and `meter: {url,token,issuer}`.
The fixture launcher restricts **all** endpoints to loopback, including the meter, so
it cannot accidentally debit a real wallet. Each server reports only role, fixture
status and listening URL. Every service binds loopback and requires a private token.
Requests and responses are capped at 96 KiB, HTTP RPCs at ten seconds, and accepted
in-flight HTTP requests at 32. No plaintext HTTP mode is available for production.

The generic `DemiPassMeter` adapter checks the separately provisioned `conduit-keys`
tenant, `release` action, zero margin, exact 2-DD price/cap, recipient-bound call
verification, signed charge receipt/issuer, and authenticated idempotency lookup.
It cannot provision a tenant or consent, raise a cap, or fall back to `post`.

Every release requires a recipient-signed grant (`makeGrant`) and each guardian's
separately signed approval (`approve`, using that guardian's distinct approval key).
These helpers are fixture building blocks; they do not simulate operator consent
or assert that a real DemiPass approval federation has been enrolled.

Use the executable four-process integration test as a configuration example. It
creates disposable keys and fake billing, kills a guardian and the coordinator,
checks restart recovery, and removes the fixture state after the test.

```sh
npm ci --ignore-scripts
CONDUIT_TEST_SOURCE=/absolute/path/to/conduit-candidate npm run test:sealed
npm test
```

Without `CONDUIT_TEST_SOURCE`, the cross-repository relay test is explicitly skipped.
All other fixture tests run. A passing local test is not live billing or independent custody.

## Security limits and remaining release gates

This is a new application protocol over HPKE (RFC 9180), AES-256-GCM, Ed25519 and
Shamir shares. The combined protocol has **not** had an independent cryptographic
review. The HPKE implementation does not claim a formal audit. The Shamir dependency
links upstream audits; those do not certify this application.

Production remains held for:

- Actual independent custodians and review of host, administrator, credential and
  recovery roots. Unique strings and three same-host processes prove none of that.
- A trusted enrollment-evidence verifier and issuer policy, with governance-approved
  policy transitions, revocation, secure backups, key rotation and tested restoration.
  Current local pinned policies are immutable; there is no production rotation API.
- Guardian-specific human/organizational approval integration. A DemiPass billing
  token is never a guardian proof. The common coordinator must not hold approval keys.
- Production service registration, consent and 2-DD zero-margin price publication;
  TLS deployment, per-principal abuse limits, monitoring, retention and operator runbooks.
  The present billing API also needs an atomic quote/maximum-total condition (or an
  enforced immutable-price policy) before live use: a concurrent administrator price
  change between precheck and charge can be detected afterward but cannot be undone
  by this adapter. No real charge was made to validate that race.
- A separate independent review and actual cross-host positive/refusal/recovery proof.

The threshold tolerates one **unavailable** guardian. When all three respond, the
coordinator retains all authenticated responses; the recipient can recover from one
signed but incorrect or undecryptable share if the other two are correct. It first
checks every signature and message/recipient/policy/grant binding, then tries at most
three pairs against the sender-authenticated gate ciphertext. Unknown guardians,
duplicates, changed bindings and invalid signatures still reject the whole package.
This is bounded recipient-side recovery, not a proof that every guardian is honest.

One incorrect share plus one unavailable guardian cannot be recovered. The coordinator
cannot inspect the encrypted shares for correctness, so an authenticated package can
still incur the fixture 2-DD charge yet fail recipient decryption. A refund/dispute
policy remains a live release gate. No refund or successful decryption is inferred
from delivery. Existing paid packages with only two responses stay immutable: this
change does not silently fetch new shares, charge again or repair historical packages.
Billing buys a delivered authenticated release package, not a guarantee that the
endpoint retains its private key or successfully processes plaintext.

Transport delivery, capsule publication, prepared quorum, paid package, client
decryption and application consumption are distinct events. The current journal has
prepared/paid records; it does not claim an independently witnessed decryption ack.
Paid retries may recover the same package after grant expiry, but cannot change
recipient or acquire new authority. A lost paid journal holds; recovery/refund is
manual. Journal hash chains detect accidental corruption, not a root rewriting history.

Encryption does not hide addresses, timing, length or whether encryption was used.
There is no padding, traffic-analysis resistance, forward secrecy or ratchet in v1.
An authorized recipient can retain plaintext; revocation cannot recall it. Existing
plaintext messages and backups remain plaintext. Do not advertise hidden target value.

Wire size is measured in the build receipt. The November 12 measurement predates
retaining a third response and is not an updated size claim. Besides base64 (~4/3), signed keys,
capsules and independent RPCs add overhead. This fixture sends the bounded envelope
to each guardian to verify its signature, so **total release traffic** is substantially
larger than the single relay envelope. It is not a blanket “less than 5x” promise.
