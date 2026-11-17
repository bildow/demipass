# Conduit Wave 3: revocation and checkpoint rehearsal

Implementation candidate. No production custodian, issuer, or recovery authority is
selected or provisioned. Live guardian release and its proposed 2-DD total fee
remain disabled. These modules are absent from MCP and from live guardian paths.

## Flight A: signed status evidence

`sealed/revocation.js` evaluates three short-lived status records against the
Wave 2 enrollment evidence and independently supplied issuer/deployment pins.
Each record contains exactly:

```
format: "conduit-guardian-status-v1"
policy_hash, guardian_id, issuer_id, serial, state, issued_at, expires_at, signature
```

`serial` is a positive safe integer; `state` is `active` or `revoked`. The issuer
signs the complete canonical body excluding signature, with the same pinned
Ed25519 key that signed that guardian's enrollment. Records cannot predate the
previous accepted issue time, be future-dated or expired, or span more than five
minutes. Missing/unknown/malformed/unsigned records refuse the evaluation. The
earliest enrollment/status expiration bounds the result. The checker clock must
be trusted; no skew tolerance or claim of instantaneous revocation is made.

Each guardian has a checkpoint of serial, complete-record hash, issue time and
sticky revocation. Lower serials and different records at the same serial refuse.
A higher `active` record cannot undo a previously observed revocation for this
policy. Any revoked member holds the entire policy, conservatively, even if two
other members remain active. A policy/trust-pin change requires separate operator
acceptance; there is no implicit rotation or re-enrollment path here.

Success is `evidence_current`, **not permission to release or charge**. A valid
revocation returns `hold`. Every result includes `live_guardian_release: false`.
Exceptions, nonzero CLI exits, missing replies and lock refusals also mean HOLD.

## Flight B: durable fixture checkpoint and recovery

```
sh sealed/revocation.sh PRIVATE_DIRECTORY PRIVATE_REQUEST_FILE
```

The existing directory must be owned by the current user, mode 0700, and not a
symlink. Request files are private, owned regular JSON files (0600), containing:

```
{fixture:true, mode:"evaluate", expected_checkpoint:"new" | "<previous hash>",
 policy, evidence, trusted, snapshots}
```

The wrapper holds a kernel `flock` on descriptor 9 for the complete Node process.
The journal uses append, hash-chain verification, complete-write loops and fsync.
A competing writer exits 3; crashes release the kernel lock. This is cooperative
same-UID process exclusion, **not** a boundary against the user/root that owns the
directory and can alter the process or lock inode. No same-host independence is
claimed. The inherited-descriptor check is not attestation of a remote custodian.

The caller must supply the checkpoint it last accepted. First bootstrap is an
explicit `new`, never an automatic fallback on missing/corrupt storage. A trust
context hash binds policy and issuer/deployment pins. The journal is committed
before returning current evidence; a revocation is committed even though its
verdict is HOLD. Repeated identical records do not append duplicate state.

On write/fsync uncertainty, the process returns HOLD with nonzero exit. A fresh
process verifies and re-fsyncs replayed state. An operator may inspect it with
`{fixture:true,mode:"inspect"}` to reconcile an uncertain append. Inspection
validates the complete checkpoint schema before returning `inspect_only` and a
checkpoint hash; malformed contents refuse without rewriting state. It does not certify current
status or reset state. Do not replace a known newer checkpoint with an older
value merely because inspection returned it. Preserve the external checkpoint
and evidence when investigating rollback. Never truncate the journal to repair it.

The fixture store does not provide an independent remote anchor. An administrator
who can replace both the journal and the caller's saved checkpoint can rewind
both. Production requires an independently retained checkpoint/witness and
verified custody, plus a real feed transport and enforcement at the release
boundary. This wave does not claim to implement those. Existing message logs,
identity keys and payment journals are untouched.

## Flight C: checks and review

`node --test test/sealed-revocation.test.js` covers signature/policy binding,
expiry, forks, rollback and sticky revocation, real subprocess restart and lock
exclusion, termination of a lock holder, missing/corrupt/truncated/old storage,
and a failed checkpoint fsync followed by reconciliation. All identities and
state are disposable fixtures. Full SDK/relay compatibility and independent
exact-head review are required before this candidate lands.

No runtime installation is part of this work. Reverting the added offline modules
is code rollback only: preserve checkpoint state and the sealed-aware relay.
Future source must not reinterpret `evidence_current` as live key-release authority.
