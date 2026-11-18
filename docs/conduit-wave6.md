# Conduit Wave 6 — readiness, installation, live acceptance

Campaign: guarded Conduit MCP. Wave 5 C2 completed with one real 2-DD charge,
signed recovery/replay and durable dispute evidence; local fixture guardians did
not establish independent custody. SDK base: 6b473ad543625b480ff9172282d0a344fb170e27.

This is Flight A's source candidate. It does not finish Wave 6. No live guardian
release, issuer provisioning, live pane onboarding, or production installation is
performed. Aaron retains actual custodian selection and final enablement.

## Dependency map and ownership

| Flight / sortie | Deliverable | Dependency / present boundary |
|---|---|---|
| A1 | Typed read-only readiness through SDK, CLI and MCP | Implemented here; independent source review required |
| A2 | Brain, Claude and Codex endpoint interoperability and refusal controls | Implemented local MCP fixture tests; not actual model sessions |
| A3 | Custodian/issuer/endpoint selection and independent control evidence | Aaron; distinct labels/signatures alone never close it |
| B0 | Brain inbound policy and tests in Tome; server refusal while missing | Operator-required hold; readiness records it, server enforcement not yet verified |
| B1 | Production service and MCP guarded-request implementation | Still unbuilt; fixture-only runners remain explicitly disabled for live work |
| B2 | Per-custodian installation, source/config receipts, restore/rollback | After A3 and independently accepted B1; not installed |
| C1 | Preserved real encrypted transport/release/ack and failure matrix | After B2; current six-peer-path tests are local direct-mode fixtures |
| C2 | Independent review of exact installed evidence and operator acceptance | After C1; Aaron closes the campaign |

The builder owns this source branch only. Fleetgate supplies independent source
review; no self-review is substituted for it. Other panes' worktrees and live
Brain/Claude/Codex configurations are preserved. The runtime is model-neutral:
Brain is an independent participant, not an alias for whichever model it uses.

## Readiness interface

`conduit_sealed_readiness` takes **no arguments**. It reads only launcher-selected
private local files; it does not create directories or endpoint identities,
discover authority from a relay, send a message, mint a token, spend DD, write a
journal or change service state. The SDK export is `conduitSealedReadiness({})`.
The CLI is `node sealed/readiness-cli.js` and shares exactly the same inspection.

Launcher configuration:

```
DEMIPASS_SEALED_READINESS_CONFIG=/absolute/private/operator-readiness.json
DEMIPASS_SEALED_READINESS_EVIDENCE=/absolute/private/guardian-evidence.json
```

The two files must differ, be current-user-owned regular files, not symlinks,
and have no group/other permissions. FIFO/nonregular inputs refuse without
blocking. Malformed input reports typed generic reasons, never parser excerpts,
private input contents or credential values. Missing configuration returns hold.
No `DEMIPASS_TOKEN`, service consent or sealed-identity opt-in is required to
inspect readiness. An MCP caller cannot supply a path, key, clock, live flag or
approval in tool arguments, even if it ignores the advertised JSON schema.

Config schema (all fields required):

```json
{
  "format": "conduit-readiness-v1",
  "participants": [
    {"role":"brain", "mailbox":"brain", "public_key":null},
    {"role":"claude", "mailbox":"claude", "public_key":null},
    {"role":"codex", "mailbox":"audit-brain", "public_key":null}
  ],
  "source_sha256": null,
  "policy": null,
  "trusted": [],
  "previous": null
}
```

These example addresses do not register or reserve any actual names. The three
roles are the required participants in this campaign; mailboxes must be their
separately reconciled stable addresses. Put an independently pinned **public**
identity in each public_key slot; null records an explicit missing prerequisite.
Mailbox and key must agree. Shared mailboxes, roles or endpoint keys refuse.
Participant keys cannot also act as guardian or enrollment authorities. No
private keys, passwords, bearer tokens or approval codes belong in either file.

`policy` is the existing fixed 2-of-3 guardian policy; `trusted` is the existing
operator-selected issuer pin list. Do not copy trust keys from an applicant's
evidence. `previous` is the separately retained revocation checkpoint; null is
only an explicit operator assertion of no previous checkpoint, never a repair
for missing/corrupt history. Inspection cannot establish the truth of that
assertion and must not be used to replace runtime checkpoint reconciliation.

Evidence schema is exactly `{evidence:[...], snapshots:[...]}` from Waves 2/3.
The existing signature, source binding, expiry, revocation, serial rollback,
same-serial fork and sticky-revocation checks are reused. Observation returns a
checkpoint hash but does not install or advance it. `config_canonical_sha256` and `evidence_canonical_sha256` bind the report to
canonical parsed JSON values (`digest_format: sha256-canonical-json-v1`), not
raw file bytes. Formatting and key-order changes intentionally have the same
digest. The evidence digest is emitted only after successful validation. Inspect again immediately before use;
this point-in-time report is not a persistent authorization.

`source_sha256` pins the canonical hash of the actual local SDK runtime inventory:
index.js, mcp-server.js, http-json.js, services.js, package.json
and every regular file directly under sealed/. A missing/mismatched pin holds.
Generate the digest on an independently reviewed artifact with:

```
node -p "require('./sealed/readiness').sourceDigest()"
```

The inventory deliberately excludes package-lock.json: npm does not ship it.
Dependency/lock verification belongs to the separate installation receipt.
Inventory reads reject symlinks/nonregular files. The digest is **not** proof of
running process identity, Node/dependency integrity, immutable filesystem mounts,
or host administrative independence. Those remain installation evidence. No
applicant-provided shell command or source path is executed by this inspector.

## Meaning of results

- `hold`: missing, invalid, expired, revoked or mismatched inspected inputs.
- `fixture_evidence_current_live_disabled`: fixture-labelled inputs validate.
- `evidence_current_live_disabled`: signed inputs validate against locally pinned
  reviewed-labelled inputs. This does not prove their physical independence.

Every result has `live_guardian_release:false`, explicit deployment blockers and
limits. CLI exit0 means the inspected evidence is current; exit2 means hold. It
never means permission to start a live service. Production service implementation,
guarded MCP integration and actual deployment/acceptance are deliberately listed
as open, not hidden behind an apparently green readiness label.

Aaron's 2026-11-18 requirement holds Brain inbound until its policy and tests are
in Tome. Every readiness result therefore also includes `brain_inbound` with
`state: hold`, `enabled: false`, a missing-evidence reason, `tome_commit: null`
and `server_enforcement: not_verified`. No argument, environment flag or provided
hash enables Brain in this implementation. This is a readiness refusal, not proof
that an existing relay was reconfigured. The production server must enforce the
hold before Brain's Wave6 route is activated, including direct, thread, forwarding
and recovery paths. A future enabling change must cite and verify the exact Tome
commit containing the inbound policy and tests; a bare hash or this hold ruling
does not satisfy that requirement. Crypto fixture success cannot open the route.

The hold is on Brain inbound. Of the six local directed-pair fixtures,
Claude-to-Brain and Codex-to-Brain require server refusals in production; four
directions remain eligible under their other gates if Brain outbound is enabled.
The existing six-pair crypto test is not a production admission test. No test or
policy for Brain's real memory ingestion is claimed here, and none is installed.

## Tests and remaining acceptance

`node --test test/sealed-readiness.test.js` exercises actual JSON-RPC MCP entry
points, unsafe/malformed input, source drift, all status refusals, and six directed
Brain/Claude/Codex endpoint exchanges. Each endpoint has separate fixture keys;
tests require deferred capsule delivery, correct decryption and signed ack, and
reject wrong recipients. No external model, existing pane, relay delivery or
real guardian is involved in those six exchanges. Existing relay integration
and payment tests remain separate evidence classes.

Later installed acceptance must include authentic model endpoint identities,
relay sent/delivered receipts, recipient decryption acknowledgment, actual
independent guardian approvals, loss/revocation/timeouts, process restart,
retained checkpoint reconciliation, archive restore, bounded billing and dispute
intake. A service restart or a fixture result cannot replace that evidence.

Rollback of this additive inspector is a source rollback. Preserve all existing
keys, ciphertext, histories, checkpoints and paid journals. Never replace live
guarded traffic with an older runner that omits a release gate. This branch
installs no unit, timer or network listener and provisions no custodian.
