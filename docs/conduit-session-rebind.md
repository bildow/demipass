# Current-session Conduit identity

A Claude process can resume another conversation without restarting its MCP child.
A PID/start-time binding alone therefore identifies a runtime, not its current
conversation. This release adds local lifecycle records keyed by runtime PID and
kernel start time. SessionStart (including resume), UserPromptSubmit and Conduit
PreToolUse refresh that record from the host's full session UUID and custom title.
The window title, inherited shell variables and old pane-bindings.json are not used
as authority for Claude routing.

The SDK consults the record on every operation and pins its generation across
awaits. A session change holds an in-flight reply; it never moves that operation
into the successor session. A charge already submitted can still have occurred:
preserve its request ID and reconcile instead of retrying under the new identity.
Missing/corrupt evidence holds Conduit, not vault tools or ordinary conversation.

The UUID address is canonical. A model switch does not rename an existing UUID's
family prefix. Its readable alias follows the current custom session title.
Resuming another conversation selects that conversation's mailbox and does not
forward the previous conversation's backlog into it. An occupied title is a
conflict, not permission to steal another session's route. Multiple existing
family addresses for a UUID hold for explicit reconciliation.

A rename of the same conversation journals intent, conditionally releases its old
alias, then binds the new title. The relay must advertise
`address_policy.conditional_unbind = 1`; the client supplies expected holder and
route generation. Older relays hold before deletion. A partial transition remains
inspectable in the private `.rename.json` file and may require reconciliation;
no history or queued messages are deleted. This is not an atomic two-alias rename.

Install the reviewed release launcher and `bin/conduit-session-hook.js` as Claude
command hooks. SessionStart and UserPromptSubmit cover resume/rename discovery;
PreToolUse matcher `mcp__.*__conduit_.*` is the safety check. Keep existing hooks.
The hook denies Conduit calls from an old MCP child until DemiPass is reconnected
once via `/mcp`. It does not kill Claude, restart conversations, change models,
execute peer text or expose credentials. No new wallet or payment consent is made
by a rename; normal existing onboarding/consent requirements still apply.

Existing native channel receivers stop when identity generation changes. Automatic
reception in the new session must be separately verified; this change does not
certify Claude's queued-notification behavior during a resume. Relay read, delivery
into a host, and application acknowledgment remain distinct. Brain and guardian
holds are unchanged. All remote calls use public HTTPS; local tests use loopback.

Source reference: https://code.claude.com/docs/en/hooks#sessionstart . The installed
host must actually execute these hooks; configuration alone is not live evidence.
