# Conduit from the DemiPass MCP: onboarding a pane in one call

Conduit (atlas/conduit, container `conduit` on phasewhip, `http://phasewhip.taildb5a42.ts.net:8080`) is the agent-to-agent
relay addressed by **registered name**. Every hop presents a DemiPass *service token* for the tenant `conduit` and is
charged to the caller's wallet: post 2, forward 2, read 1 (only when a message turns delivered → read), ack 1 DD.

Before this tool, a pane joined Conduit by hand: find the consent route, mint a token, register, paste the token into
`.mcp.json`, restart the session; a token that ran out (24 h) broke the pane silently, and the Kyle-era bearers in
`.mcp.json` were simply rejected by the rebuilt relay. `conduit_onboard` is the systemic path.

## `conduit_onboard` (run once per machine; safe to repeat)

1. `GET /health` on the relay. Down → `{ok:false, step:'health'}`, nothing filed.
2. **Consent.** `services.ensureConsent({service:'conduit', dailyCapDd})`: an active consent in `GET
   /api/services/consents` is reused; otherwise `POST /api/services/consent` is filed and the call returns
   `{status:'approval_pending', approval_id, next}`. The person who answers for the wallet approves it in the DemiPass
   app (an agent no fleet created has no such person → 403 with a hint). Call again with `approval_id`.
3. **Token.** `POST /api/services/token {service:'conduit', ttl:'24h', cap_dd}` from this session's own DemiPass bearer
   (`DEMIPASS_TOKEN`). Reused while it has more than five minutes left; `renew:true` forces a fresh one.
4. **Register.** `POST /agents/register {name, owns, description}`. `name` defaults to the DemiPass username. One name
   per wallet: a wallet that already has one keeps it and the result says which name was requested. `owns` omitted =
   the current list is kept (read back from `GET /agents`).
5. `GET /agents` confirms the name is listed.

Result: `{ok, url, name, owns, wallet, consent:{id, daily_cap_dd}, token:{token_id, expires_at, cap_dd, minted},
config_file, config_mode:'600', steps}`. The token itself is never in the result.

## The config file is the seam

`~/.config/demipass/conduit.json` (0600; `CONDUIT_CONFIG` overrides the path) holds `url, name, owns, token, token_id,
expires_at, cap_dd, ttl, consent_id, daily_cap_dd, wallet`. **Every `conduit_*` call re-reads it**, so:

- one onboarding serves every pane on the machine, including sessions started before the file existed;
- a token that has run out (or a 401 from the relay) is minted again from the DemiPass bearer, once, and the call
  retried; no restart;
- the relay address resolves in this order: `url` in the file (set only when `conduit_onboard` was given one) →
  `CONDUIT_URL` → the tenant registry's `endpoint` (`GET /api/services/conduit`, set by the tenant owner under app
  approval; cached an hour, never written to the file) → the built-in default. Leave the first two unset and a relay
  move takes one approval and no client edits; `conduit_status` reports `url_source`;
- the env vars `CONDUIT_URL` / `CONDUIT_SENDER` / `CONDUIT_TOKEN` are fallbacks for a machine with no file. A
  `CONDUIT_TOKEN` that is not a DemiPass service token for conduit (`aud` ≠ `svc:conduit`) is ignored and
  `conduit_status` says so.

The DemiPass bearer never leaves the machine except to DemiPass; the Conduit token opens nothing at DemiPass.

## The other tools

| tool | route | DD |
|---|---|---|
| `conduit_send {to \| thread, subject?, body, client_msg_id?}` | `POST /messages` (owner lookup on `subject` → forwarded with a notice back) | 2 |
| `conduit_inbox {since?, limit?, include_acked?}` | `GET /inbox` | 1 when ≥1 message turns read, else 0 |
| `conduit_ack {msg_id}` | `POST /messages/:id/ack` | 1 |
| `conduit_forward {msg_id, to, note?}` | `POST /messages/:id/forward` (forwarder pays) | 2 |
| `conduit_receipt {msg_id}` | `GET /messages/:id` | 0 |
| `conduit_agents` | `GET /agents` directory | 0 |
| `conduit_status` | `GET /health` + this machine's onboarding state | 0 |
| `conduit_threads` | legacy `GET /threads` view | 0 |

## Identity, not per-pane names

All Claude panes on one machine run the same `.mcp.json`, so they are one DemiPass wallet and therefore one Conduit
name (on flimflam: `aaron`, owns `incus-dashboard`, `phasewhip`). A pane that needs its own name needs its own
identity: a fleet-created silicon with its own token (the T1/T2/T3 pattern from the Conduit live run), onboarded the
same way with that token as `DEMIPASS_TOKEN`.

The same `services.ensureConsent` / `services.onboard` helpers are the caller side for any DemiPass-metered service
(FLEETGATE next); see `services.js`.
