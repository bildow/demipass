# Wave 6 runtime build: guardian test preparation

This source implements an operator-armed TLS guardian/coordinator runner and four
bounded MCP operations. No live config, permit, custodian, issuer, key, wallet or
service is provisioned by this build. It is not independent-custody acceptance.

## Local authority boundary

`node sealed/installation-plan.js /absolute/instance guardian|coordinator|endpoint`
prints a read-only plan, source digest and command. `service.sh` and `endpoint.sh`
require a private, owner-controlled 0700 directory and retain an exclusive flock
through the Node process. Endpoint calls run in a bounded 45-second child with
bounded input/output. Every retry keeps its original envelope/fee/grant identity.

An instance has private config.json (0600). Service config is the existing fixture
shape, with fixture:false, policy.assurance:reviewed, permit_file, tls:{key,cert},
and optional host/port. Guardian keys are local to their custodians. The coordinator
holds public guardian keys and three distinct transport tokens, not guardian secret
shares or approval private keys. All outgoing service calls require HTTPS and normal
certificate validation; no HTTP live fallback, redirect or insecure TLS option.
The listener uses TLS 1.3 or later. Permit checks run before each live request.

A permit is an operator-created private JSON file:

```
format: conduit-runtime-permit-v1
state: armed
role: guardian | coordinator | endpoint
policy_hash: canonical policy SHA256
source_sha256: installation-plan source digest
custody_tome_commit: exact 40-character reviewed custody-record commit
acceptance_sha256: exact independent source acceptance receipt SHA256
expires_at: UTC epoch milliseconds, future and at most 24 hours away
```

No code creates this file or offers an MCP enable tool. These hashes bind the local
operator's decision; the runtime does NOT fetch Tome or prove that a hash represents
valid acceptance. Before creating any real permit, Aaron must select genuinely
independent custodians and inspect the cited records. A service owner capable of
rewriting local code/config is outside this enforcement boundary. Runtime checks
reject forged JSON capabilities, wrong role, changed/deleted permit, changed source,
expired permit, self-asserted reviewed policy and absent authority. Signed enrollment
and revocation gates still run at the release boundaries. Do not treat an armed
listener as proof that its current evidence will authorize release.

## Endpoint configuration and operations

Set DEMIPASS_SEALED_RUNTIME_DIRECTORY in the MCP launcher only. Private config:
format:conduit-endpoint-runtime-v1; permit_file; policy; admission:{trusted,feed_file,
expected_checkpoint}; sender and recipient pinned public identities; coordinator:
{url,token}; payer_token_file (private JSON {token}); payer_wallet; meter_issuer;
client_directory. No tools accept these paths or credentials. Each real endpoint
must possess only its own Client key. Sender/recipient keys cannot double as guardian
or issuer keys. The named Brain recipient remains refused here; relay admission
must separately pin all actual Brain aliases before any installation.

- conduit_guarded_prepare: plaintext/public_text/padding. Pins recipient/policy
  from config, seals locally, durably saves ciphertext/capsule, defers the capsule.
- conduit_guarded_grant: envelope/capsule. Pins sender/policy, persists one signed
  recipient grant per envelope. Does not contact a guardian or pay.
- Custodians examine the bound grant and use `node sealed/guardian-approve-cli.js
  PRIVATE_APPROVAL_CONFIG PRIVATE_REQUEST_FILE` locally. Approval config contains
  guardian_id, approval_identity, policy, sender, recipient. A shared approval token
  cannot satisfy another guardian. Copy only public signed approval output.
- conduit_guarded_release: request_id/approvals/padding. Uses the persisted original
  request, at least two distinct approval signatures, configured HTTPS coordinator
  and dedicated payer token. Checks signed original 2-DD/zero-margin receipt and
  payer, saves paid evidence, decrypts locally and returns a signed acknowledgment.
- conduit_guarded_dispute: request_id/complaint. Routes a recipient-signed complaint
  for an original paid request; no extra debit or automatic refund. It is intake,
  not evidence of a human resolving the complaint.

Endpoint checkpoint-pin.json advances atomically under the OS lock after the status
journal changes. Missing/mismatched pins hold instead of resetting. A crash between
journal and pin writes requires explicit reconciliation against original evidence.
This local anchor cannot detect restoring an entire old machine state: separate
custodian feeds/checkpoints and operator restore validation remain necessary.
Services retain the existing explicit expected_checkpoint restart protocol.
Do not reset a checkpoint to 'new' to make a restart pass.

An expired grant is not automatically replaced. Recovery can return a previously
paid package after guardian revocation; no new release can use revoked evidence.
Missing local paid state, a bad receipt or uncertain response holds. Keep the
original request id and reconcile; do not mint a replacement to retry payment.

## Evidence required to finish acceptance

Tests use disposable local keys, a test CA and a signed simulated meter. They
exercise the actual MCP child, OS lock, TLS coordinator, crypto and return path,
including duplicate calls and process restart. They do not establish real physical
custody, real model consumption, real service installation or a new paid acceptance.
Wave 5's one real 2-DD payment remains separate historical evidence; no additional
real payment is authorized by these fixtures.

Before live guardian testing: independently accept this exact source, install on
selected custodian hosts, reconcile real public identities/issuers, retain signed
source/config and restore receipts, prove the server's Brain refusal, then authorize
one bounded end-to-end test budget. Preserve transport sent/delivered timestamps,
recipient signed decrypt/ack, timeout/revocation/restart/restore evidence and paid
receipt. Brain remains excluded until its own inbound policy/tests are in Tome.

No Wave 6 closure may be inferred from source tests, a permit template, or a listener.
