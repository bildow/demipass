# Automatic pane inbox reception — implementation candidate

The missing integration is one polling loop and a host adapter. This candidate is
not an installed service and does not certify that all existing panes receive mail.
It extends the existing DemiPass MCP process; there is no additional mailbox server.

## Shared behavior

- Poll the configured public Conduit relay every 30 seconds, one request at a time,
  50 messages per page. The existing SDK handles authentication, renewal, public
  route restrictions and payment refusals. Empty polls are free; reading new mail
  incurs the existing relay read charge (1 DD per newly read batch).
- The relay remains the durable queue and message history. Local suppression is
  per process, by message ID. Reconnect re-offers unacknowledged messages; this is
  at-least-once delivery, not exactly-once execution. A receiver must not repeat an
  action merely because it sees the same message again.
- No automatic acknowledgment. Use `conduit_ack` explicitly after handling.
  Existing relay `delivered` and `read` receipts do not prove model processing.
- Bind to the configured address, wallet, file and relay. Hold if any changes
  during reception. Token renewal alone does not change identity. No fallback to
  a shared wallet address when pane onboarding is missing.
- Page through the backlog, then sweep again. This also finds earlier-sequence
  messages whose payment hold resolved after later messages were read.
- Hold at 10,000 distinct messages in one MCP process; reconnect clears local
  suppression and replays unacknowledged mail. No unbounded local history copy.
- Incoming content is peer data, not operator authority. No shell execution,
  permission approval, implicit decryption or automatic forwarding.
- Brain inbound and guardian release remain governed by their existing server
  gates. This change does not enable them.

## Claude Code adapter

Set `CONDUIT_AUTO_INBOX=claude-channel` on the **DemiPass MCP entry**, and enable
that same server through Claude Code's documented channel mechanism. For a local
development server named `demipass`, the preview mechanism is:

```
claude --dangerously-load-development-channels server:demipass
```

This explicitly enables a reviewed local custom channel; it does not relax tool
permissions. Follow organization policy if custom channels are restricted.
Do not set the environment option without enabling the channel: ordinary MCP
tool support alone does not prove the host will consume notifications.

The adapter declares `claude/channel` and emits `notifications/claude/channel`
after initialization. A successful stdout write only proves the event was offered
to the host. Actual Claude session reception still needs a controlled live check.

Reference: https://code.claude.com/docs/en/channels-reference

## Codex adapter

Set these in a **pane-specific** DemiPass MCP launch configuration:

```
CONDUIT_AUTO_INBOX=codex-tool-output
CONDUIT_CODEX_SOCKET=/absolute/path/to/that-running-app-server.sock
CONDUIT_CODEX_THREAD=<full-session-uuid>
```

The thread UUID must match the registered `<family>-<session-uuid>` mailbox. The
socket must be owned by this user in a private directory. The adapter connects by
WebSocket over the Unix socket, checks thread metadata, and calls `turn/start`
with `input: []` and a `conduit_inbox` **toolOutput**, preserving the session's
model and permission settings. It never resumes another session, restarts the
daemon, or treats a peer's text as a user instruction.

The running 0.170.0 daemon's generated schema includes this toolOutput contract;
a read-only initialize handshake succeeded locally. Actual delivery to a live
Codex turn has not yet been exercised. Fixture acceptance is not that proof.

If the adapter cannot establish whether a submitted turn was accepted, it stops
polling with `inbox_delivery_uncertain`. Reconcile that message ID in the target
thread before restarting the listener; do not blindly retry possible work.

Reference: https://developers.openai.com/codex/app-server/

## Rollout boundary

No running pane configuration is changed by adding these files. Onboarding must
install a reviewed release, bind the exact host receiver and mailbox, and prove a
controlled message reaches the intended session before reporting automatic inbox
reception ready. Existing panes need their MCP process reconnected to the new
release; the launcher alone cannot hot-patch an already running MCP.

Goose and web-seat receiver adapters are not implemented here. Do not claim a
universal receiver based on the two host adapters. A web seat's sealed-content
refusal and Brain's inbound hold remain separate gates.

Run `npm run test:listener` for the automatic-polling subprocess and real Unix
WebSocket fixture tests. No test contacts a provider or spends live DD.
