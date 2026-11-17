# Conduit Wave 4: release boundaries and endpoint lifecycle

Source candidate, not a deployed release system. Live guardian release, production
custodians and the proposed 2-DD fee remain disabled. Same-host keys/processes are
fixtures. Wave 5 economics and Wave 6 independent deployment remain separate.

## A: required status gate on real fixture service paths

Guardian and Coordinator now require `ReleaseGate`, not a boolean approval or
caller-supplied check callback. A gate owns separately configured policy/issuer
pins, a checkpoint journal, a trusted clock and a bounded local feed. The feed
contains exactly `{evidence,snapshots}` from Waves 2/3. Release requests cannot
supply issuer pins, time, prior state or the status feed. Signatures do not prove
independent administration; independent acceptance of pins remains external.

Fixture service config adds:

```
admission: {trusted: [...], feed_file: "/absolute/private/feed.json",
            expected_checkpoint: "new" | "<last independently retained hash>"}
```

The feed must be an owned, private regular JSON file, max 128 KiB; combined status
validation retains Wave 3's 96-KiB limit. It is read afresh at each check. A trusted
operator/feed producer should atomically replace it; partial writes fail closed.
No feed producer, refresh daemon, remote issuer transport or privileged key is
provisioned here. Missing, malformed, expired or unverifiable feed holds new work.
Pins are loaded from private service configuration, never inferred from the feed.

`status.jsonl` is the same format used by the Wave 3 checkpoint CLI, under the
instance's existing OS lock. The exact caller checkpoint must match at startup.
After first use, restarting with stale `new` refuses. Retain the last checkpoint
outside the instance; stop the instance and use `revocation.sh` inspect to reconcile
uncertain appends before updating the operator config. Inspection alone is not
permission to replace a known newer checkpoint or accept new trust. Never delete
or truncate a journal to get past this check. Config/policy changes require a
separately accepted transition; existing journal context cannot silently change.

Guardian checks occur before cache replay, after HPKE work and again after share
persistence, before disclosure. Time validity is rechecked after checkpoint fsync. The coordinator checks before requesting shares, after
remote replies before preparing a package, and after asynchronous meter precheck
immediately before an unpaid charge. Revocations persist before the gate throws.
A failed checkpoint write poisons that gate until restart/reconciliation. All
fresh/unpaid work remains held even if previously issued status was active.

Paid retry is intentionally different: after original recipient proof and payer
binding, only the original prepared recipient-encrypted package can be recovered.
An uncertain charge is looked up under the original key before any new charge.
Confirmed payment can reconcile despite new revocation; no new guardian share or
recipient is authorized. This cannot revoke previously disclosed keys. There is
no claim of atomicity between a remote charge and a local status change: the last
unpaid check precedes charge dispatch; Wave 5 must finish the economic contract.

The shell lock remains cooperative same-UID exclusion, not malicious-user/root
isolation. Static FIFO/directory/symlink/shared lock paths refuse before open.
Private-file reads use nonblocking open so a FIFO refuses instead of hanging.
Directly bypassing the wrapper or changing its code is outside that boundary.

## B1: endpoint acknowledgment and optional padding

`conduit_sealed_prepare` accepts `padding: "none" | "1k" | "4k" | "16k"`.
Default remains `none`. A selected bucket creates a random fixed-size binary
frame with a typed marker, byte length and UTF-8 plaintext; the base64url frame is
then encrypted by the unchanged signed v1 envelope protocol. A 1-KiB frame fits
1005 plaintext bytes; 4/16-KiB frames fit 4077/16365 bytes. Overflow refuses rather
than silently selecting a larger bucket. Padding adds overhead and hides only
within-bucket content length, not addresses, timing, bucket size or encryption use.
No automatic format detection: recipients select the same `padding` when opening.
Ordinary unpadded envelopes remain compatible. Wrong framing, length or UTF-8 refuses.
No plaintext or padding hint is placed in the public header automatically.

`conduit_sealed_open` optionally accepts `acknowledge:true`. Only after actual
successful decryption and requested frame decoding does it create a recipient-
signed `conduit-decryption-ack-v1`, save it privately and return it with plaintext.
The ack contains the envelope/capsule hashes, recipient pin, optional immutable
release hash, padding choice and endpoint timestamp; never plaintext, keys or a
plaintext digest. Existing valid receipts replay without rewriting; corrupt or
uncertain storage refuses. The timestamp comes from the endpoint clock after
decryption/decoding, never from request arguments; replay retains the original
signed time. The endpoint timestamp is an assertion, not trusted
external delivery time. `verifyAcknowledgment` requires pinned sender/recipient
and exact envelope/release/padding bindings.

This is a recipient-signed assertion of endpoint decryption. A holder of its signing
key can manufacture assertions. It is not proof a person/model read or understood
anything, nor a relay delivery receipt. No automatic ack transmission or extra DD
charge occurs; a caller may explicitly send the public signed receipt separately.

## B2: explicit transition review and archive recovery

`policy-transition.js reviewTransition` is an offline, non-mutating fixture review.
Input includes current policy/pins/enrollment/status and retained prior checkpoint,
next policy/pins/enrollment, a typed proposal, approvals and checking time. It accepts
only the existing fixed 2-of-3 policy shape, exactly next epoch (+1), valid next
enrollment, and a proposal bound to both policy/pin contexts and current evaluated
checkpoint. Proposal lifetime is at most five minutes and cannot exceed evidence.

Two or three distinct current guardian approval authorities sign
`{purpose:"conduit-policy-transition-v1",guardian:<own ID>,proposal:<exact body>}`.
This explicit purpose/audience cannot reuse a grant approval. Revoked current
members cannot vote; two remaining current members may review the next epoch.
New guardians cannot authorize their own transition. Output is only
`fixture_transition_reviewed_not_installed` with `live_guardian_release:false`.
It does not install pins, consume a production governance nonce, enroll custodians,
rewrite old capsules or change any key. Actual installation needs independent
operator/custodian acceptance and durable deployment/governance controls in Wave 6.
Unknown status or insufficient governance quorum holds; no emergency bypass exists.

Archive recovery restores the *same* independently pinned endpoint identity through
Wave 2's encrypted offline backup to a fresh private directory. Existing identity,
ciphertext, status history and paid packages are preserved. A new session/mailbox
binding does not inherit a predecessor key. New epochs apply to separately prepared
new envelopes; there is no automatic old-message rewrap or deletion of old keys.
The checker establishes signature/binding eligibility only, not true independence.

## C: evidence and landing gates

Run `node --test test/sealed-release-gate.test.js test/sealed-services.test.js
 test/sealed-endpoint-lifecycle.test.js test/sealed-policy-transition.test.js
 test/sealed-backup.test.js`, then full `npm test` with `CONDUIT_TEST_SOURCE` for
the relay compatibility case. Fixtures exercise revocation during actual awaits,
paid/uncertain-paid recovery, restarted HTTP services, MCP invocation, private FIFO
refusal, epoch/governance negatives and restore/decryption of pre-loss ciphertext.
Independent exact-head Fleetgate review and CI are required before source landing.

Rollback is a source rollback only. Preserve endpoint keys, acknowledgments,
status and release journals; do not restart an older service that ignores the new
status gate against an active guarded workload. No production installation is
part of this source wave. Do not interpret review of this fixture path as approval
to enable production release, bootstrap trusted issuers or activate billing.
