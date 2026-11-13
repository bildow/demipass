# FleetEngine from a pane

FleetEngine carries CSP's engines as one metered service. It is a DemiPass **service tenant** (`fleetengine`), and any
wallet that consents pays it in Diamond Dust. Results can also be delivered over Conduit. The ruling is tome
`decisions/2026-11-12-DECISION-fleetengine-and-shadow-engine-redefinition.md`; the service is Forgejo `atlas/fleetengine`.

The pane client is `fleetengine-mcp.js` (bin `fleetengine-mcp`). It is built the same way as `fleetgate-mcp.js`.

## Attach

    demipass-onboard fleetengine            # or the demipass MCP tool demipass_onboard_service

This files a consent ("let a wallet pay fleetengine"). The person approves it once in the DemiPass app. The command
then adds a `fleetengine` entry to `~/.mcp.json`. The entry is pinned to the onboarding wallet (`DEMIPASS_EXPECT_DID`)
and holds no session copy: the server reads the live session whenever it needs one.

## Tools

| tool | cost | |
|---|---|---|
| `fleetengine_onboard({daily_cap_dd?, approval_id?})` | free | consent (one app approval) + a service token held in memory only |
| `fleetengine_status()` | free | onboarded? token expiry, consent, service health. Files nothing. |
| `fleetengine_engines()` | free | the engines the service runs |
| `fleetengine_prices()` | free | the tenant's price list, margin included |
| `fleetengine_run({engine, requisition, job_id?})` | **real** | one job: an intake charge, then metered model calls |
| `fleetengine_job({job_id})` | free | state and outcome. Only the paying wallet can read it. |
| `fleetengine_pattern_run({pattern, inputs?, delivery?, job_id?})` | **real** | a shadow (pattern) engine run: engines chained |

### The requisition

    { "pool": { "files": [ { "path": "spec.md", "content": "…" } ] },   // or git {url, ref?}, or url
      "effort": "scan | standard | deep",
      "premise": "the framing the engine works under",
      "concern": "the focus",
      "delivery": { "conduit_name": "aaron" },
      "max_dd": 1000 }

## Money

- **Intake.** A run makes one intake charge (`job`).
- **Metered work.** The engine's model calls bill afterwards at cost plus the tenant margin, in portions of at most
  250 DD. Each portion is a follow-up of the intake charge.
- **Follow-up budget.** The token is minted with `follow_up_dd` = the whole daily consent. That lets the work bill after
  the token has expired.
- **Ceiling.** A job meters at most its `max_dd`, or by effort: scan 250, standard 1000, deep 5000.
- **Running out.** A job the wallet can no longer pay for ends as a **certified refusal**, never a silent partial.
- **Retries.** `job_id` is the idempotency key. A retry with the same `job_id` replays the intake charge and finds the
  job, so it never charges twice. If the connection drops, the answer carries the `job_id` to retry with.
- **Refusals.** DemiPass's refusals come back as DemiPass gave them: 401/402/403, and its own 202 when an approval is
  pending. A DemiPass 202 is never mistaken for a queued job.

The token is never printed, returned or written to disk. It is used only by the wallet that minted it, and it is
re-minted on expiry or on a 401.

Env: `DEMIPASS_TOKEN` or the live session, `DEMIPASS_URL`, `FLEETENGINE_URL`, `FLEETENGINE_DAILY_CAP_DD` (default 3000).
The endpoint is resolved in this order: `FLEETENGINE_URL`, then the DemiPass registry, then
`https://repo.dustroot.com/-/fleetengine`. It must be https, except a loopback host.
