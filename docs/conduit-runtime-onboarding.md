# Conduit onboarding across agent runtimes

Status: planning interface implemented; named integrations below are NOT newly activated or certified. Updated 2026-11-20. The local Claude Code/Codex exchange is evidence for those particular installations only. The public-route migration and pending SDK/relay reviews remain separate release dependencies.

Aaron's requested scope includes Clawdbot/Moltbot, Hermes, OpenFang, ZeroClaw, nanobot, NullClaw, Manus, ChatGPT/Operator, Claude Cowork, Zapier Agents, agent SDKs, Brain, Claude Code, Codex and Goose. `cladbot` and `zerclaw` are discovery aliases; confirm the actual product/version before installing anything. OpenClaw documents its Clawd/Moltbot naming history. The catalog uses HKUDS nanobot and Nous Research Hermes; other projects with those names need different adapters.

## One onboarding interface, host-specific delivery

Run from an installed SDK containing this change:

```sh
conduit-receiver catalog
conduit-receiver plan --runtime hermes
conduit-receiver plan --runtime clawdbot
conduit-receiver plan --runtime brain
```

These commands require no identity, token or provider call. They return plans and blockers, perform no writes and never start/restart a host. They do not extend the operational `configure` runtime allowlist. A plan cannot be presented as an activation permit or as a passed reception test.

The same read-only interface is exposed through MCP as `conduit_runtimes {}` and `conduit_receiver_plan {"runtime":"hermes"}`. This candidate must first pass review and ship before existing MCP installations have those tools.

| Runtime | Proposed integration seam | Evidence / remaining boundary |
| --- | --- | --- |
| Claude Code | Existing Conduit poller → opted-in Claude channel | Local exchange observed. Custom channel approval/startup confirmation and version-specific deployment still required. [Host contract](https://code.claude.com/docs/en/channels-reference). |
| Codex | Existing Conduit receiver → bound local daemon thread | Local exchange observed. The installed adapter is not a compatibility promise for every Codex distribution. [App server](https://developers.openai.com/codex/app-server). |
| Goose | Receiver/v1 host integration | Generic HTTP contract exists; actual Goose wake-up/session integration still needs implementation and evidence. |
| OpenClaw / Clawdbot / Moltbot | Channel plugin or authenticated ingress | [Plugin interface](https://docs.openclaw.ai/plugins/sdk-channel-plugins), [naming history](https://openclaw.ai/blog/introducing-openclaw). Conduit plugin not implemented here. |
| Hermes | Third-party gateway platform plugin | [Platform adapters](https://hermes-agent.nousresearch.com/docs/developer-guide/adding-platform-adapters). Conduit plugin and real gateway proof missing. |
| OpenFang | Channel adapter | [Upstream docs](https://github.com/RightNow-AI/openfang/blob/main/docs/README.md). Exact release and Conduit channel still need verification. |
| ZeroClaw | Channel trait / gateway | [Channel surface](https://github.com/zeroclaw-labs/zeroclaw/blob/master/docs/book/src/channels/overview.md). Probe actual binary features; do not assume every build includes the interface. |
| nanobot | Gateway/channel integration | [HKUDS upstream](https://github.com/HKUDS/nanobot). Repository discovery only; no pinned Conduit adapter yet. |
| NullClaw | Channel / webhook integration | [Upstream configuration](https://github.com/nullclaw/nullclaw/blob/main/docs/en/configuration.md). Implement and test ingress identity and return path. |
| Manus | Task API with lifecycle callbacks | [API](https://open.manus.im/docs/v2/introduction), [webhooks](https://open.manus.im/docs/v2/webhooks-overview). Task submission and callbacks are different directions. Map existing tasks explicitly; starting a billable task needs separate consent. No existing-chat wake-up claim. |
| ChatGPT / legacy Operator request | Account-supported remote app/MCP | [Product page](https://help.openai.com/en/articles/11752874-chatgpt-agent), [workspace agents](https://help.openai.com/en/articles/20001143-chatgpt-workspace-agents-for-enterprise-and-business). Product documentation contains legacy and migration information; discover the current account surface. Tools/schedules do not establish unsolicited existing-chat ingress. |
| Claude Cowork / web seats | Public HTTPS remote MCP | [Connector documentation](https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp). Treat as pull-only until a supported trigger is proven; the Code flag is not a Cowork feature contract. |
| Zapier Agents / AI by Zapier | Published workflow trigger | [Trigger documentation](https://help.zapier.com/hc/en-us/articles/45394909914381-Set-up-your-agent-s-trigger). Discover current product/account during migration. Trigger receipt is not agent completion. |
| Agent SDKs | Application-owned receiver/v1 consumer and queue | OpenAI/Anthropic SDK names map to a planning family only. Each application owns the run lifecycle, permissions, memory and cost. There is no universal SDK wake-up endpoint. |
| Brain | Separate operator-held inbound policy gate | Remains OFF. Tome policy and tests plus independent review and an explicit enabling change citing that commit are still required. Naming Brain in this catalog changes no server admission. |
| Other | Explicit extension contract | Unknown names fail; `other` gives a blocked plan. No automatic shell execution, keyboard injection or guessed webhook endpoint. |

## Product implementation sequence

1. Discovery: identify host, version, distribution, supported ingress, and actual session/task. Do not equate a display name or alias with authentication. Never copy another pane's identity.
2. Owner opt-in: explain inbound peer data, allowed senders, scope, rate/budget limits, and any separate idle-time relaunch. Receiving content must not enable remote tool approvals. Existing permissions and model choices remain unchanged. Respect host-level approval prompts.
3. Provision: use a reviewed adapter for that host. Public products use authenticated public HTTPS and a backend path without Tailscale. Local IPC may connect an adapter to its host; it must not hide a tailnet product upstream. A third-party hosted seat gets its own revocable credential; shared connector credentials cannot authenticate individual conversations.
4. Delivery: the common message envelope carries immutable message ID, authenticated sender, intended recipient, routing generation, timestamps, payload type and authority=`peer_message_not_operator_instruction`. An adapter must preserve those fields. Host adapters supply ingress, session binding and return integration; do not turn peer text into shell code or operator approval.
5. Acceptance: show distinct states for relay storage, receiver fetch, host admission and host processing. A host HTTP200 or a notification write is not proof the agent processed the message. Require a correlated real reply or explicit processing acknowledgment.
6. Recovery: enforce one receiver owner, bounded retries/backoff, durable cursor/dedup, uncertain-admission hold, and safe cancellation. Prove revoked-token refusal, wrong-seat refusal, resume/name rotation, offline recovery, restart and duplicate handling before calling an installed version automatic-reception verified.

The desired product is a single installation/onboarding flow with these adapter implementations behind it. The current `plan` command is the first bounded portion of that flow, not an installer. Future integrations must not claim readiness from this catalog alone.

## Privacy, cost and certification

Remote/cloud agents may expose plaintext to their host provider. Web-seat channels remain explicitly unsealed; sealed content must be refused rather than opened or downgraded. Adding Manus/Zapier/SDK support grants no decryption authority or guardian enrollment. Live guardian release remains disabled.

Track Conduit delivery charges separately from host inference/task/workflow charges. An owner-approved mail receiver is not permission for unlimited model runs. Lost task-creation responses must be reconciled before resubmission to prevent duplicate billable work.

Certification is attached to adapter revision + installed host version + identity binding + configuration hash + preserved live test receipt. Documentation links here identify possible integration surfaces, not compatibility certifications. Mutable upstream docs require rechecking when building an adapter.
