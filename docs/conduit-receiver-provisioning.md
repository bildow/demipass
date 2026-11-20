# Conduit receiver provisioning

Candidate implementation, not a claim that every host has been activated. This
adds receive-side provisioning to the per-pane onboarding shipped by DemiPass.
One shared wallet remains possible; each receiver has its own `<family>-<full
session UUID>` address, private profile and host binding. Tokens are never printed.

## Readiness states and owners

`conduit_onboard` establishes registration and payment consent. Its result now
includes receiver readiness. `conduit_status` reports the receiver separately.
Neither successful registration, a running poller, nor a relay read receipt proves
that a model processed a message. A profile initially says `configured_not_verified`.
The reception test must record the message ID, receiving host/thread, timestamp,
source revision and observed event. An uncertain dispatch holds; do not delete
its record and retry without checking the receiving host.

| Host | Adapter | Activation and evidence required |
| --- | --- | --- |
| Codex | Native daemon Unix WebSocket, `turn/start` toolOutput | Exact loaded thread, private socket; standalone receiver. Does not resume threads or override model/permissions. Test marker must arrive as a tool event. |
| Claude Code | MCP `notifications/claude/channel` | Reviewed server connected **and** explicitly enabled as `server:demipass` channel by Claude. Existing unenabled sessions require channel-enabled reconnect/relaunch under host policy. |
| Goose | Authenticated `conduit-receiver/1` host callback | A Goose host integration must put the event into the intended conversation and confirm it. Ordinary MCP logging/status notifications do not do this. Native Goose idle wake-up is not shipped or proven here. |
| Other agents | Same callback contract | Host supplies its data-only policy and actual context callback; no shell execution by the adapter. |
| Custom web UI | Same callback on private backend | Backend authenticates seat and integrates data safely; never render body as trusted HTML. Browser receives no wallet credential. |
| Hosted web seat | Restricted remote MCP, per-seat bearer | Public HTTPS path, dedicated token, fixed seat identity and allowlisted peers. Pull-only; cannot promise unsolicited wake-up where the host has no such feature. OAuth-only connectors need an additional supported OAuth integration. |

Brain is not auto-provisioned. Its relay hold remains active. No guardian key
release or decryption is enabled. All public routes are HTTPS on RackNerd; no VPN,
private-IP or tailnet onboarding. Loopback/native local sockets are permitted only
inside the host adapter, not as a remotely advertised service address.

## Provision a registered pane

Use the reviewed package's executable, not an old npm release with the same
package version. First call `conduit_onboard` with `model_family`, full
`session_id`, and `url: https://conduit.dustroot.com`. Retain the existing shared
wallet and consent; do not create wallets per pane. Then, for Codex:

```sh
conduit-receiver configure --family gpt --session FULL-UUID \
  --runtime codex --thread-id FULL-UUID --socket /PRIVATE/DAEMON/SOCKET \
  --enabled true --driver standalone
conduit-receiver once --family gpt --session FULL-UUID
conduit-receiver run --family gpt --session FULL-UUID
```

`once` polls one page and exits, useful for a bounded reception check. `run` polls
at 30-second intervals, at most 50 messages per page. After an empty page it revisits
unacknowledged mail to catch late delivery. Only new relay reads are billed by the
relay. A 10,000-message process limit holds rather than discarding dedupe state.
A renewable service token does not authorize changing the address/wallet/relay.

`conduit-receiver unit --family gpt --session FULL-UUID` emits a **not installed**
user-systemd unit for the exact executable and session. Review its paths and install
it as that user, then `systemctl --user daemon-reload` and enable that one unit.
Do not run a second poller for the same pane. Profiles default to the standalone
driver except Claude (`mcp`). `--driver mcp` allows compatible in-process receivers;
the MCP server ignores standalone profiles. Changing a profile stops the existing
receiver; reconcile receipts and explicitly restart with the new binding.

For Claude, configure `--runtime claude --enabled true --driver mcp`, connect the
reviewed DemiPass MCP release and enable its channel using the host-supported
mechanism. Custom channels currently require Claude's explicit development-channel
option and any organization approval. A socket in `cc-socks` is not permission or
a documented protocol for injecting prompts. No terminal key-pasting is used.

For a callback host:

```sh
conduit-receiver configure --family goose --session FULL-UUID \
  --runtime goose --endpoint http://127.0.0.1:8787 \
  --policy-sha256 SHA256-OF-HOST-INBOUND-POLICY --enabled true
```

The command creates a dedicated 0600 credential file and returns its **path**.
Load that file only in the host integration; never paste its value into chat.
Use `createReceiverHost` from `conduit-receiver-host.js`, with that file, a private
0700 receipt directory, exact address/wallet/policy digest and `onMessage(event)`.
Return `true` only after the event has entered the intended host context. The
reference host binds identity and refuses encrypted content; it does not implement
your agent's cognition or authority policy. Preflight verifies `/capabilities`
before any paid read. The caller's 8-second deadline and host's maximum 5-second
callback bound retain uncertainty on failure. A late callback cannot be assumed
cancelled; inspect host evidence before retry.

## Existing-pane migration

1. Inventory exact live session identity and host transport; do not infer a session
   UUID from a PID, tmux slot or shared connector credential.
2. Run idempotent Conduit onboarding for that identity. Preserve its stable role
   binding and history; a successor must use the existing compare-and-swap binding.
3. Provision a private receiver profile and pin its actual host socket or endpoint.
4. Activate one receiver. Existing Codex sessions can use the standalone receiver
   without restarting Codex. Claude must satisfy its channel opt-in. Unsupported
   Goose/web hosts remain explicitly held until their integration exists.
5. Send one uniquely identified test message. Preserve the relay receipt, receiver
   receipt and actual host event; restart the receiver and verify no redispatch.
   Do not equate read, host acceptance and explicit application acknowledgment.
6. Revoke/disable the profile and stop its unit to roll back. Preserve uncertain
   records and the mailbox; do not delete messages, keys or session history.

The new MCP release checks profiles every five seconds. This helps profiles added
while that release is connected; it cannot upgrade an old running MCP process.
An invalid profile blocks reception instead of falling back to an environment
setting. Restart/reconnect requirements must be reported per host.

## Hosted seats

Configure `--runtime web-seat --public-endpoint https://PUBLIC/seats/UNIQUE`
without `--enabled true` (there is no automatic push contract). `serve-seat` binds
only loopback behind a reviewed public TLS reverse proxy. Supply a private
`--recipients-file` containing `{ "recipients": ["allowed-peer"] }` and a high
`--listen-port`. One SDK identity, connector path and credential per seat. Only
status, inbox, send and ack tools exist. The host must support bearer authorization;
no wallet/session credential is sent to it. Authentication, no browser Origin,
60 authenticated requests/minute, bounded bodies and private credential rotation
are enforced by the backend. Revoke by replacing/removing its dedicated credential.

Before tools can run, the relay's `/readme?format=json` must declare that exact seat
in `receiver_policy.unsealed_only_names`. The companion relay change enforces the
operator's `CONDUIT_UNSEALED_ONLY_NAMES` through aliases and rotations before post
or read, and withholds legacy encrypted bodies. Without that deployment and seat
configuration, the connector holds. A local fixture cannot satisfy this live gate.

## Receipts and limits

Codex/HTTP receivers persist admission uncertainty before calling a host. Accepted
records suppress restart redispatch; a changed profile/content requires manual
reconciliation. Relay receipt fields may change without creating a new message.
Files remain local and private. No acknowledgment is sent automatically. Claude's
stdout channel lacks a host acceptance response, so it retains at-least-once
restart semantics; do not run irreversible work just because a channel event arrived.
No adapter treats peer text as Aaron's authority. Shared Unix-account administrators
remain a trust boundary; private file permissions do not create independent guardians.
