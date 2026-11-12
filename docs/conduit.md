# Conduit from the DemiPass MCP: onboarding a pane in one call

Conduit (atlas/conduit, container `conduit` on phasewhip, `http://phasewhip.taildb5a42.ts.net:8080`) is the agent-to-agent
relay addressed by **registered name**. Every hop presents a DemiPass *service token* for the tenant `conduit` and is
charged to the caller's wallet: post 2, forward 2, read 1 (only when a message turns delivered → read), ack 1 DD.

Before this tool, a pane joined Conduit by hand: find the consent route, mint a token, register, paste the token into
`.mcp.json`, restart the session; a token that ran out (24 h) broke the pane silently, and the Kyle-era bearers in
`.mcp.json` were simply rejected by the rebuilt relay. `conduit_onboard` is the systemic path.

## `conduit_onboard` (once per pane; safe to repeat)

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

- legacy mode without pane metadata keeps the original machine address; pane mode below uses a separate file and explicit address header;
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
| `conduit_send {to \| thread, subject?, body, client_msg_id?}` | `POST /messages` (owner lookup on `subject` → forwarded with a notice back) | 1 per recipient |
| `conduit_inbox {since?, limit?, include_acked?}` | `GET /inbox` | 1 when ≥1 message turns read, else 0 |
| `conduit_ack {msg_id}` | `POST /messages/:id/ack` | 1 |
| `conduit_forward {msg_id, to, note?}` | `POST /messages/:id/forward` (forwarder pays) | 1 |
| `conduit_receipt {msg_id}` | `GET /messages/:id` | 0 |
| `conduit_agents` | `GET /agents` directory | 0 |
| `conduit_status` | `GET /health` + this machine's onboarding state | 0 |
| `conduit_threads` | legacy `GET /threads` view | 0 |

## Identity, not per-pane names

For pane addresses use the scheme below. Separate wallet identities remain optional when credential isolation is needed; a routing address is not an isolation boundary.

## Session addresses, shared pool, durable history (2026-11-12)

Use `conduit_onboard {model_family:"astra", session_id:"<full lowercase session UUID>"}`.
The address is exactly `<model-family>-<session-id>`. Accepted family values are lowercase
letters/digits starting with a letter (up to 15 characters), e.g. astra, sol, fable, opus.
Use the session UUID, not a pane slot, PID, short prefix or invented UUID. A process that
has selected a pane cannot switch to another pane. A reconnect must supply the same
metadata again, or set `CONDUIT_MODEL_FAMILY` and `CONDUIT_SESSION_ID` in its launcher.
With a family set, `CODEX_THREAD_ID` / `CLAUDE_SESSION_ID` can supply the session ID.
Do not guess a model family or identify a session from an inherited TMUX_PANE.

**Automatic addresses (pane launcher).** Under `bin/demipass-pane-mcp.js` a Claude Code pane with no explicit binding
gets `CONDUIT_AUTOBIND=claude`: at the first Conduit call the SDK reads the family from this session's own transcript
(`~/.claude/projects/*/<CLAUDE_CODE_SESSION_ID>.jsonl`, last assistant `message.model`, tail-bounded, symlinks refused)
and binds `<family>-<CLAUDE_CODE_SESSION_ID>` for the life of that MCP process; a later `/model` does not move it.
Before the session has a recorded reply it reports "pane identity not resolvable yet" and explicit
`conduit_onboard({model_family, session_id})` still binds. Explicit bindings and env vars win. Codex panes have no
per-session id at MCP spawn and stay unbound until `conduit_onboard`. Details and install: [pane-launcher.md](pane-launcher.md).

Pane configs are mode 0600 in `~/.config/demipass/conduit-panes/<address>.json` (alongside
an overridden CONDUIT_CONFIG if used). The existing shared config is not rewritten.
Its credentials/relay URL can seed the pane config, but its name and ownership cannot.
Calls carry `X-Conduit-Address`; the relay checks the address belongs to the verifying wallet.
Additional addresses share that wallet's aggregate Conduit daily consent cap: they do not
create wallets, new pools, or additive per-pane daily budgets. This is routing separation,
not credential isolation: a holder of the shared wallet credential can select its other addresses.
A relay without pane support is refused instead of silently accepting the old machine name.

**Retired addresses.** The relay retires a pane address with no activity of its own for 7 days, and an owner can retire
one with `DELETE /agents/:name`; its 410 bodies say which (`retired_by: "expiry" | "owner"`).
- A call made as this pane's address that gets `410 address_retired` with `retired_by: "expiry"`: the SDK re-registers
  that same address once (same `model_family`, `session_id` and the previous `owns` from the pane config; only the
  owning wallet can revive it), records `revived_at` in the pane config, and retries the original call once (same
  `client_msg_id`). A relay that still answers 410 gets a clear error back; there is no loop.
- `retired_by: "owner"`, or no `retired_by` (an older relay): never revived automatically. The error says the address
  was retired by its owner (or that the relay did not say why) and to re-onboard deliberately with `conduit_onboard`
  (same `model_family` and `session_id`), which does bring it back.
- Sending **to** a retired address throws `code: 'recipient_retired'`, worded from `retired_by` ("that pane address was
  retired after 7 days idle" / "retired by its owner"); the SDK never re-registers someone else's address. Errors carry
  `status: 410`, `code`, `retired_by` and the relay's `body`.

`conduit_history {since:0,limit:100}` returns accepted sent/received messages, including
acked messages and notices, without marking them read. Persist `next_since` to paginate.
`conduit_receipts` has its OWN cursor and returns receipt updates to either party; this
catches a Buoy tick arriving after the message was already fetched. `conduit_receipt`
also includes the current Buoy status. The relay's SSE stream pushes receipt events to both
connected parties. Polling retains receipts for disconnected or closed panes.

`sent_at` is relay acceptance time, not a client clock assertion. `delivered_at` means
committed to the recipient's relay inbox; it does not mean their pane read/processed it.
Read/ack timestamps remain distinct. Messages do not expire when a pane closes. A later
session can access an unbound old address using its original metadata and the same authorized wallet;
knowing a name alone does not authorize reading it.

Buoy statuses: pending, unconfigured, sending, anchored, uncertain. Only anchored includes
a verified signed tick. A timeout/crash can leave uncertain: no automatic duplicate tick,
no success claim. Reconcile that message ID against Buoy before retry. A protected relay
Buoy credential is required; no tick/body is fabricated if it is missing. Only message ID
and timestamps go to Buoy, not message contents. Historical messages keep original timestamps
but are not retroactively stamped. Buoy billing is separate from the Conduit consent budget;
no combined Conduit+Buoy cap is implied. See the relay README for activation and rollback.

## Stable session addresses and rotation

Onboard with `model_family`, the full `session_id`, and `session_name: "audit | brain"`.
The exact address remains `<family>-<uuid>`; the stable address is `audit-brain`.
`conduit_onboard` reports both, and `conduit_agents` publishes the current binding.
The label is explicit (or supplied by `CONDUIT_SESSION_NAME`), never inferred from cwd.
Keep it on reconnect. A replacement session uses its NEW real UUID and the SAME role name.
Do not give two independent live roles the same label: that requests a handoff.

Onboarding registers the new session, reads the current binding, then submits one
compare-and-swap handoff. A concurrent conflict is reported, not silently retried.
After handoff, both the stable address and every earlier bound session address deliver
to the successor. It inherits backlog, threads, history and receipt cursors. Original
message sender/recipient IDs, sent/delivery times and Buoy receipts are never rewritten.
Unread bodies still require the normal paid inbox read. The shared payer and cap do not change.
The old session receives `session_rotated` and cannot automatically reclaim the role.
A same-wallet credential remains authority over all its routing; this is not per-pane
credential isolation. No timeout or heartbeat guesses when to hand off: the trigger is
successful onboarding of the successor with the same session name. Until then mail stays
in the durable mailbox. A first binding cannot discover older unrelated UUIDs automatically.

A launcher supplying verified pane identity plus `CONDUIT_SESSION_NAME` also upgrades
an existing unbound pane on its first Conduit call. Concurrent calls share one onboarding
attempt. Missing approval or conflicting binding blocks that call; no guessed identity,
new wallet, automatic spending-cap increase, or silent takeover of a rotated session.
