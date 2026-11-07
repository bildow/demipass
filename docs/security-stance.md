# DemiPass Security Stance

## Custody Boundary

DemiPass is a **client SDK**. All security-critical operations happen on the Dustforge server:

- **Encryption**: AES-256-GCM at rest, server-side. The SDK never handles raw encryption.
- **Secret storage**: Secrets are stored in Dustforge's database, encrypted with the platform master key.
- **Token issuance**: 30-second, single-use tokens are generated server-side.
- **Secret injection**: Passwords and API keys are injected into SSH commands, HTTP headers, etc. by the server. The SDK receives results, never the secret value.

## What the SDK Does

- Provides MCP tool definitions with behavioral descriptions
- Wraps Dustforge API calls with ergonomic functions
- Auto-creates contexts when missing (self-healing)
- Manages Bearer token authentication

## What the SDK Does NOT Do

- Store secrets locally
- Encrypt or decrypt values
- Validate contexts or enforce access control
- Run an independent policy engine

## Trust Model

The SDK trusts the Dustforge server for:
- Secret storage and encryption
- Token lifecycle (issuance, expiry, single-use enforcement)
- Velocity throttling and suspension
- Trust gradient computation
- Referral tracking

The Dustforge server trusts the SDK caller for:
- Bearer token authenticity (JWT with DID claim)
- Correct use of ref codes (routing addresses, not secrets)

## Threat Model

| Threat | Mitigation |
|--------|-----------|
| Secret in context window | Use-token model — secret never enters prompt/completion |
| Stolen Bearer token | 24h expiry, per-DID rate limits, velocity throttle |
| Ref code guessing | Ref codes are routing addresses, not secrets. They grant token requests, not secret access |
| MITM on API calls | HTTPS required. Server rejects HTTP. |
| Prompt injection via secret description | Server-side injection filter blocks code patterns |
| Exfiltration attempt | Velocity throttle: 5 distinct secrets in 30 min = auto-suspend |
| A service (tenant) replays a caller's token at DemiPass | Service tokens carry `iss: demipass-svc` + `aud: svc:<tenant>`; every DemiPass route accepts only `iss: civitasvox`. The tenant can verify and charge, never act as the caller |
| A tenant overcharges or charges strangers | Charges only on a token the tenant verified, within its life; ≤ the action's published max + margin per call; ≤ the token's `cap_dd` in total; idempotent; each row carries the token id |
| A tenant learns who is behind a wallet | verify returns the wallet DID, token id, scope and depth; delegated calls carry a pairwise principal (different at every tenant), never the owner |
| A tenant skips a person's approval | Elevated service actions take the approver's phone approval (same requests as elevated secrets); lowering a depth takes the tenant owner's PIN |

### Dogfood rule

DemiPass's own repos ship through FLEETGATE (charter lane, reviewers, closer, release controller), whose authentication is
DemiPass. The bootstrap case, where DemiPass can't ship because its own gate's authentication is broken, has exactly one
exception path: declare it in a tome record before the push (the broken gate step and its measurement, the exact head,
who ordered it), log it (tome commit, Buoy tick, deploy log), and close it out by running the bypassed head through the
restored gate and recording the result. The fix restoring the gate rides alone; there is no second exception before
the first is closed out. Full text: dustforge `docs/service-tenants.md`.

## Reporting

Report security issues to support@dustforge.com or via the bounty program at dustforge.com/security.html.
