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

## Reporting

Report security issues to support@dustforge.com or via the bounty program at dustforge.com/security.html.
