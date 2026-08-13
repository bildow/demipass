# DemiPass — Sightless Write Grant (`sightless_write`)

**Date:** 2026-08-13
**Status:** proposed — not implemented, no server change yet
**Scope:** DemiPass as the authorization authority for terminal writes on Sightless surfaces
**Siblings:** `Sightless/docs/WRITE-AUTHORIZATION-BOUNDARY.md`, `brain/docs/router-system/workflow-authorization-contract.md`

---

## 1. Why this belongs in DemiPass

DemiPass already answers *"is this actor allowed to do this thing?"* for every
credentialed action in the ecosystem — `ssh_exec`, `http_header`, `http_body`,
`git_clone`, `smtp_auth`, `database_connect`. It owns the machinery that answer
requires: DID identity, fingerprint auth, trust gradient and bands, the eval spec,
velocity throttling, delegation, single-use scoped tokens, and an audit trail.

Sightless briefly grew its own parallel authorization system (Flight 6's canary
gate). It sourced authority from a *physical operator ceremony* rather than from
identity, had no override, and locked the operator out of their primary work
surface for days. The post-mortem is in the sibling Sightless spec §1.

The correction is not to make Sightless's gate better. It is to recognize that a
terminal write is **a credentialed action like any other**, and route the decision
to the component that already makes those decisions.

This matters more than it looks. A Sightless terminal write is not "type text into
a shell" — bound panes run `codex`/`claude` in YOLO / bypass-permissions mode, so
a terminal write **makes an autonomous agent with full machine access act.** By
blast radius it is the most powerful action DemiPass would govern. It is a poor
candidate for a bespoke, surface-local authorization scheme, and a natural
candidate for the trust gradient and eval spec.

The inherent use case is carbon↔silicon interaction *across surfaces*. An
authorization service scoped to a single surface cannot express that; DemiPass is
already the cross-surface identity layer.

## 2. Custody boundary (unchanged)

Consistent with `docs/security-stance.md`: DemiPass decides and issues; it does
not execute. Specifically for `sightless_write`:

**DemiPass does:**
- authenticate the actor (DID, fingerprint, trust band, eval spec);
- decide whether that actor may write to that target at this moment;
- mint a scoped, short-lived, single-use, payload-bound grant;
- apply velocity throttling and suspension;
- revoke grants and record the audit trail.

**DemiPass does not:**
- resolve workflow names to targets — that is Brain (CP-1 input, not a DemiPass concern);
- know or validate tmux internals, pane liveness, or window layout;
- perform the write, or hold a transport to the Sightless host;
- decide whether a pane is *still* the right pane at redemption — only Sightless
  can see that, and it stays Sightless's job.

Note the difference from `ssh_exec`: DemiPass does **not** inject a secret here.
There is no credential in a terminal write. What is being granted is **permission
to act on a target**, and the artifact returned is an authorization, not an
injected value. This is a new *class* of DemiPass action — an **action grant**
rather than a **secret-injection token** — and it should be modeled explicitly
rather than bolted onto the use-token path.

## 3. The grant

```json
{
  "grant_id":  "swg_01J8Z...",
  "typ":       "action_grant",
  "action":    "sightless_write",
  "sub":       "did:key:z6Mk...",
  "target": {
    "server_id":  "flimflam",
    "binding_id": "tmux-pane:c6212afc-3ce3-4a37-bd35-e8683bf920b4",
    "pane_id":    "%3",
    "pane_pid":   "2872075"
  },
  "constraints": {
    "payload_sha256": "7fc87cb7e4c264c52eeaf23638519b54e242aa34c3cd8039b47b3cb8faa97f9f",
    "max_uses":   1,
    "not_before": 1786566000,
    "expires_at": 1786566120
  },
  "trust":       { "band": "operator", "eval_ref": "eval:...", "auth_method": "fingerprint" },
  "correlation": "corr_01J8Z...",
  "issuer":      "demipass",
  "issued_at":   1786566000
}
```

**Binding properties.** The grant is bound to actor **and** exact target identity
**and** exact payload **and** single use **and** a short window. Together these
reproduce every guarantee Flight 6's canary provided — right pane, exactly once,
no replay — sourced from identity rather than ceremony:

| Guarantee | Enforced by |
|---|---|
| right actor | `sub` + trust band, checked at issuance |
| right pane | `target.*`, re-checked live by Sightless at redemption |
| exactly once | `max_uses: 1` + `grant_id` in Sightless's delivery ledger |
| no replay of other text | `payload_sha256` |
| bounded exposure | `not_before` / `expires_at` |

`payload_sha256` is deliberately a hash, not the text. **DemiPass must never
receive the terminal payload.** It authorizes a commitment to a message it cannot
read — no prompt content, no pane text, no agent output enters DemiPass. That
preserves the existing context-window stance and keeps DemiPass out of the data
path entirely.

## 4. Issuance

`POST /api/demipass/action-grant` (name provisional)

Request (from Brain or a Sightless client, **CP-1**):

```json
{
  "action": "sightless_write",
  "target": { "server_id": "flimflam", "binding_id": "tmux-pane:...",
              "pane_id": "%3", "pane_pid": "2872075" },
  "payload_sha256": "7fc87cb...",
  "requested_posture": "confirm",
  "correlation": "corr_01J8Z...",
  "reason": "route to workflow audit"
}
```

Decision inputs, in the order they should be evaluated:

1. **Identity** — valid DID, non-expired token, `auth_method` recorded. Fingerprint
   strengthens the band; it is not required for the operator's own band.
2. **Suspension / velocity** — existing throttle applies. A burst of grants across
   many distinct bindings is the terminal-write analogue of the existing
   exfiltration signal and should suspend.
3. **Trust band → posture ceiling** (§5).
4. **Eval spec** — the eval result **narrows scope**; it does not simply veto
   (see F-4 below and Sightless spec §10 Q4). A weaker eval yields a shorter TTL
   and a narrower target, not a flat refusal, so the failure mode is degraded
   capability rather than a wall.
5. **Delegation** — a delegated DID may hold write grants for another operator's
   binding only with an explicit delegation record naming that `server_id`.

Issuance is **cheap and instant**. There is no ceremony, no device requirement, and
no human step on the DemiPass side. This is the property that removes the downtime:
a grant can always be minted by a sufficiently trusted actor, at any hour, from any
network position.

## 5. Trust bands → write posture

| Band | Terminal write posture |
|---|---|
| `operator` (carbon, fingerprinted) | grants for any binding on servers they own; longest TTL |
| `trusted_agent` | grants for explicitly delegated bindings; short TTL; confirmation recommended |
| `probationary` | grants only for bindings with a recorded prior successful delivery; shortest TTL |
| `untrusted` / cold start | no `sightless_write` grants (F-7) |
| `suspended` | none, including the operator's own agents |

Cold start (**F-7**) needs an explicit answer rather than an accidental denial: a
freshly enrolled DID has no history, so a first grant must come either from an
operator-signed delegation or from an in-person fingerprint enrollment. Whichever
is chosen, it must be *stated*, because "new agent silently cannot act" is the
same class of failure as Flight 6 — a lockout nobody documented.

## 6. Revocation (CP-7)

- `POST /api/demipass/action-grant/revoke` — by `grant_id`, or all grants for a DID.
- Existing `demipass_token_revoke` semantics extend naturally; the kill switch for
  a compromised agent must also kill its outstanding write grants.
- **Push-preferred.** With pull-only introspection, the worst-case revocation
  window equals the grant TTL, and that TTL then *is* the revocation SLA and must
  be published as such (**F-10**).
- Revoking a DID's grants must never revoke the local operator override on the
  Sightless host — that override is filesystem-local and outside DemiPass's
  custody by design (Sightless spec §6). DemiPass cannot lock an operator out of
  their own machine, and must not be able to.

## 7. Audit (CP-6)

Sightless reports redemption outcomes back: `grant_id`, `delivery_id`, result,
and — when the host was in degraded/override mode — a replayed record of writes
taken without a grant, so the trail has no gap.

DemiPass records: who wrote, to which binding, when, under which trust band and
eval reference, and with which correlation id. Terminal writes become first-class
in the same audit surface as credential use, which is a strict improvement over
today, where they are only in Sightless's local ledger.

**F-8 — correlation.** Three identifiers exist: Brain's job/message id, DemiPass's
`grant_id`, Sightless's `delivery_id`. Without a shared `correlation` field
threaded from the first request, incident reconstruction is manual joining across
three systems. It is in the grant above for this reason; it must be honored on all
three sides.

## 8. Contact points

Shared IDs across all three specs — keep stable.

| ID | Edge | Direction | DemiPass role |
|---|---|---|---|
| **CP-1** | grant request | Brain / client → **DemiPass** | authenticate, decide, throttle |
| **CP-2** | grant issuance | **DemiPass** → caller | mint scoped single-use grant |
| **CP-3** | grant presentation | client → Sightless | *(none — DemiPass not in path)* |
| **CP-4** | grant verification | Sightless → **DemiPass** | signature material or introspection |
| **CP-5** | binding truth | Brain → Sightless | *(none)* |
| **CP-6** | outcome + audit | Sightless → **DemiPass** | record redemption, override replay |
| **CP-7** | revocation | **DemiPass** → Sightless | kill grant / DID mid-flight |
| **CP-8** | degraded mode | local file on Sightless host | *(none — deliberately outside custody)* |

## 9. Friction owned or shared by DemiPass

- **F-1 — DemiPass is not fully operational.** The eval/fingerprint layer is not
  live. This spec is therefore a *target*, adopted in phases (Sightless spec §9);
  nothing about today's Sightless write path changes until Phase 3.
- **F-2 — availability becomes a write-path dependency.** *This is the most
  important design constraint in this document.* If a terminal write requires a
  live DemiPass call, then a DemiPass outage is a Sightless outage — and the whole
  point of this redesign is to stop authorization from creating downtime.
  Mitigations, in preference order: **(a)** offline-verifiable signed grants (JWS)
  so redemption needs no round trip; **(b)** a short client-side grant cache;
  **(c)** the operator bail-out, which is outside DemiPass entirely. **A write
  path must never be strictly less available than the terminal it writes to.**
- **F-3 — clock skew** across flimflam / phone / racknerd against 30–120s TTLs.
  Needs a bounded, documented skew allowance.
- **F-4 — eval gates issuance vs. scope.** Recommendation: **scope**. A weak eval
  should shorten TTL and narrow the target, not refuse outright; a hard veto on an
  immature eval layer reproduces the Flight 6 lockout with a new label.
- **F-5 — double authority.** Brain's registry `policy.write` must not be a
  decision. It is a *requested posture* (CP-1 input) and a local confirmation
  requirement. Only DemiPass decides. If Brain's value can ever permit a write
  DemiPass would refuse, the split has failed.
- **F-6 — device-independent trust.** No grant decision may depend on a specific
  device being reachable. Trust is a property of the actor, not of a USB cable or
  an `adb tcpip` that does not survive reboot. This is the exact assumption that
  broke Flight 6.
- **F-7 — cold start** (§5).
- **F-9 — multi-tenancy.** The tailnet is shared (`aaronlsr42@`, `mayer.kyle@`).
  Grants carry `target.server_id`; a Sightless host must reject grants not naming
  it, and DemiPass must not issue cross-operator grants absent a delegation record.
- **F-10 — revocation latency** (§6).

## 10. Open questions

1. **Signed offline grants vs. introspection.** F-2 vs F-10 — the central trade.
   Recommendation: signed JWS with short TTL, plus push revocation, so the common
   path needs no network and the SLA stays bounded.
2. Does the phone hold its own DID and request grants directly, or does Brain
   always broker? Direct is truer to carbon↔silicon; brokered is fewer parts.
3. Should `action_grant` be a distinct object from the existing use-token, or a
   variant? Distinct is cleaner — no secret injection, different lifecycle — but
   costs a new endpoint and new SDK surface.
4. Does the SDK expose `demipass_write_grant` as an MCP tool? If agents can
   request their own write grants, the trust band is doing *all* the work, and the
   velocity throttle becomes load-bearing.
5. Rate-limit shape specific to terminal writes: per-binding, per-DID, or both?

## 11. SDK surface (sketch, not yet implemented)

```js
const grant = await demipass.requestWriteGrant({
  server_id: 'flimflam',
  binding_id: 'tmux-pane:...',
  pane_id: '%3',
  pane_pid: '2872075',
  payload_sha256: sha256(text),
  correlation: corrId,
});
// grant.grant_id — presented to Sightless alongside the write (CP-3)
```

Two notes carried from the 2026-08-13 SDK review, both of which apply directly to
this path and should be fixed before it carries write authority:

- `_request` does not enforce HTTPS; a non-`https` `baseUrl` puts the bearer token
  — and now write grants — on the wire in cleartext. Grants are authorization
  artifacts; this must be closed first.
- MCP tool descriptions must not advertise actions the SDK rejects (the lingering
  `env_inject` case). If `sightless_write` ships in a description before the
  server implements it, agents will burn cycles on an action that cannot succeed.
