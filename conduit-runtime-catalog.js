'use strict';

// Discovery/planning only. Entries do not register receiver drivers or authorize
// a host launch, provider call, spend, key release, or Brain inbound admission.
const ENTRIES = [
  { id: 'claude-code', aliases: ['claude'], label: 'Claude Code', path: 'claude-channel', stage: 'local_exchange_observed',
    seam: 'Opted-in MCP channel in a running Claude Code session.',
    blockers: ['Package and review the custom channel; respect the host startup confirmation.', 'Test the installed host version, resume/rebind and duplicate reception.'],
    sources: ['https://code.claude.com/docs/en/channels-reference'] },
  { id: 'codex', aliases: [], label: 'Codex', path: 'codex-local-adapter', stage: 'local_exchange_observed',
    seam: 'Installed local Conduit receiver delivers into the exact bound daemon thread.',
    blockers: ['This local adapter is not proof every Codex distribution exposes the same interface.', 'Pin supported host versions and verify restart/dedup on the installed release.'],
    sources: ['https://developers.openai.com/codex/app-server'] },
  { id: 'goose', aliases: [], label: 'Goose', path: 'receiver-http', stage: 'host_integration_required',
    seam: 'Conduit receiver/v1 callback contract; a Goose-specific consumer still needs certification.',
    blockers: ['Implement and verify Goose session ingress and response return; MCP tools alone do not wake it.'], sources: [] },
  { id: 'openclaw', aliases: ['clawdbot', 'moltbot', 'cladbot'], label: 'OpenClaw (Clawdbot / Moltbot)', path: 'channel-plugin', stage: 'host_integration_required',
    seam: 'Documented channel plugin or authenticated webhook ingress.',
    blockers: ['Confirm installed product/version; the cladbot spelling is a suggested match, not identity proof.', 'Implement sender policy, session mapping and durable dispatch/return.'],
    sources: ['https://openclaw.ai/blog/introducing-openclaw', 'https://docs.openclaw.ai/plugins/sdk-channel-plugins'] },
  { id: 'hermes', aliases: ['hermes-agent'], label: 'Hermes Agent (Nous Research)', path: 'channel-plugin', stage: 'host_integration_required',
    seam: 'Third-party platform plugin via the Hermes gateway adapter registry.',
    blockers: ['Implement and test platform ingress, session persistence and outbound return in the installed Hermes version.'],
    sources: ['https://hermes-agent.nousresearch.com/docs/developer-guide/adding-platform-adapters'] },
  { id: 'openfang', aliases: [], label: 'OpenFang', path: 'channel-plugin', stage: 'host_integration_required',
    seam: 'Documented messaging channel adapters.',
    blockers: ['Select an exact supported release and implement/test Conduit channel identity, ingress and return.'],
    sources: ['https://github.com/RightNow-AI/openfang/blob/main/docs/README.md'] },
  { id: 'zeroclaw', aliases: ['zerclaw'], label: 'ZeroClaw', path: 'channel-plugin', stage: 'host_integration_required',
    seam: 'Channel trait or authenticated gateway ingress; build-time features vary.',
    blockers: ['Probe the actual binary features and version; implement/test the Conduit consumer.'],
    sources: ['https://github.com/zeroclaw-labs/zeroclaw/blob/master/docs/book/src/channels/overview.md'] },
  { id: 'nanobot', aliases: ['hkuds-nanobot'], label: 'nanobot (HKUDS)', path: 'channel-plugin', stage: 'host_integration_required',
    seam: 'Project channel/gateway integration; repository discovery is not an implemented Conduit driver.',
    blockers: ['Confirm HKUDS is the intended nanobot distribution, pin its channel API, implement and test ingress/return.'],
    sources: ['https://github.com/HKUDS/nanobot'] },
  { id: 'nullclaw', aliases: [], label: 'NullClaw', path: 'channel-plugin', stage: 'host_integration_required',
    seam: 'Documented channel and webhook integration.',
    blockers: ['Pin runtime channel/session semantics and implement/test authenticated ingress and return.'],
    sources: ['https://github.com/nullclaw/nullclaw/blob/main/docs/en/configuration.md'] },
  { id: 'manus', aliases: ['manus-ai'], label: 'Manus AI', path: 'task-api', stage: 'host_integration_required',
    seam: 'Task API creates tasks or sends follow-up messages; webhooks report lifecycle events.',
    blockers: ['Task creation is a separately consented potentially billable run, not an idle existing-chat notification.', 'Implement task ownership mapping, signed webhook validation and uncertain-create reconciliation before retries.'],
    sources: ['https://open.manus.im/docs/v2/introduction', 'https://open.manus.im/docs/v2/webhooks-overview'] },
  { id: 'chatgpt', aliases: ['chatgpt-operator', 'operator', 'chatgpt-agent', 'chatgpt-work'], label: 'ChatGPT / legacy Operator request', path: 'remote-mcp', stage: 'host_capability_unverified',
    seam: 'Account-supported app/MCP integration; no unsolicited existing-chat wake-up certified here.',
    blockers: ['Resolve current product, plan and connector capabilities rather than installing a legacy Operator adapter.', 'Keep pull-only unless a supported trigger and actual recipient processing are demonstrated.'],
    sources: ['https://help.openai.com/en/articles/11752874-chatgpt-agent', 'https://help.openai.com/en/articles/20001143-chatgpt-workspace-agents-for-enterprise-and-business'] },
  { id: 'claude-cowork', aliases: ['cowork'], label: 'Claude Cowork', path: 'remote-mcp', stage: 'host_capability_unverified',
    seam: 'Remote MCP connector; Claude Code channel flags do not establish Cowork reception.',
    blockers: ['Use a public HTTPS connector and supported account authentication.', 'Keep pull-only until a documented host trigger and processing test establish more.'],
    sources: ['https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp'] },
  { id: 'claude-web', aliases: ['claude-ai'], label: 'Claude web seat', path: 'remote-mcp', stage: 'host_capability_unverified',
    seam: 'Per-seat public HTTPS connector; message tool access does not prove background reception.',
    blockers: ['Bind sender identity to the authenticated seat; enforce unsealed-only content.', 'Keep pull-only without an independently verified host trigger.'],
    sources: ['https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp'] },
  { id: 'zapier-agents', aliases: ['zapier', 'ai-by-zapier'], label: 'Zapier Agents / AI by Zapier', path: 'workflow-trigger', stage: 'host_integration_required',
    seam: 'Published workflow/MCP trigger or schedule; product migration requires version/account discovery.',
    blockers: ['Configure a specific authorized workflow; webhook acceptance is not agent processing.', 'Pin run/task mapping, verify duplicate delivery and budget limits before enabling triggers.'],
    sources: ['https://help.zapier.com/hc/en-us/articles/45394909914381-Set-up-your-agent-s-trigger'] },
  { id: 'agent-sdk', aliases: ['agent', 'agent-sdks', 'openai-agents-sdk', 'claude-agent-sdk', 'anthropic-agent-sdk'], label: 'Application-owned agent SDK', path: 'receiver-http', stage: 'host_integration_required',
    seam: 'Application implements Conduit receiver/v1 around its own queue and agent runner.',
    blockers: ['Select the specific SDK/version; this generic contract is not certification for every SDK.', 'The application owns permissions, scheduling, inference spend, persistence and reply integration.'], sources: [] },
  { id: 'brain', aliases: [], label: 'Brain', path: 'policy-held', stage: 'operator_policy_hold',
    seam: 'No inbound activation while the operator-held Brain policy gate is closed.',
    blockers: ['Tome commit must contain Brain inbound policy and tests, independently reviewed.', 'An explicitly authorized enabling change must cite that commit; policy must address memory and action authority.'], sources: [] },
  { id: 'other', aliases: ['custom'], label: 'Other runtime', path: 'unselected', stage: 'host_capability_unverified',
    seam: 'Discover a documented host interface before choosing a transport.',
    blockers: ['Implement an adapter against the shared contract; do not silently fall back to shell or terminal input.'], sources: [] },
];

function clone(value) { return JSON.parse(JSON.stringify(value)); }
function catalog() {
  return { schema: 'conduit-runtime-catalog/v1', researched_at: '2026-11-20',
    purpose: 'integration planning; not a list of certified or enabled receivers', runtimes: clone(ENTRIES) };
}
function plan(name) {
  if (typeof name !== 'string' || !name.trim() || name.length > 80) throw Error('runtime_name_required');
  const requested = name.trim().toLowerCase();
  const entry = ENTRIES.find(x => x.id === requested || x.aliases.includes(requested));
  if (!entry) throw Error('runtime_unknown');
  return { schema: 'conduit-onboarding-plan/v1', requested_runtime: requested, ...clone(entry),
    state: entry.id === 'brain' ? 'held_by_operator_policy' : 'plan_only',
    writes_performed: false, host_started: false, automatic_reception_enabled: false,
    reception_verified: false, externally_certified_versions: [],
    content_authority: 'peer_data_not_operator_instruction',
    sealed_delivery: ['remote-mcp','task-api','workflow-trigger'].includes(entry.path) ? 'refuse_until_separate_explicit_policy' : 'not_granted_by_plan',
    network_policy: 'public_https_service_routes_no_tailnet_backend; explicit_local_host_ipc_only',
    required_evidence: [
      'exact host product/version and adapter source revision',
      'distinct authenticated agent/seat identity and exact session/task binding',
      'owner opt-in for reception, allowed senders, rate/spend limits and any separate idle restart',
      'actual message processed by intended host with correlated reply or explicit acknowledgment',
      'wrong identity, revoked credential, duplicate, restart, rebind and offline/uncertain-delivery controls',
      'no permission elevation, automatic remote approval or unsafe sealed-content downgrade',
    ],
  };
}
module.exports = { catalog, plan };
