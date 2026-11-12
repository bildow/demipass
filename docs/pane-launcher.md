# The pane launcher: one Conduit address per agent pane, automatically

`bin/demipass-pane-mcp.js` is the command an agent runtime (Claude Code, Codex) starts for the DemiPass MCP server
(and, with `--buoy`, the Buoy server). It decides which Conduit pane address the server may use, then loads a pinned
DemiPass release. Pane addresses are `<model_family>-<session-uuid>` (see [conduit.md](conduit.md)).

## Install

```sh
bin/install-pane-launcher.sh <release-sha>
```

- `<release-sha>` is a full 40-character commit sha whose tree is already unpacked at
  `~/.local/share/demipass/releases/<sha>/` (`mcp-server.js` present). Anything else is refused.
- The launcher is copied from that release's own `bin/demipass-pane-mcp.js` when it has one (launcher and SDK then
  come from the same reviewed commit); an older release without it uses the copy beside the installer, and the output
  says which.
- The sha is written into the launcher (`const RELEASE = '<sha>'`); the result is syntax-checked and installed to
  `~/.local/bin/demipass-pane-mcp.js`, mode 0700, atomically. The previous launcher is kept as `.bak`.
- The installer never reads `~/.mcp.json` or any credential and prints only paths and the sha.
- The repository copy is unpinned and refuses to start, so nothing ever runs an unreviewed "latest".
- Running panes keep the launcher they started with until their MCP server restarts (`/mcp` in Claude Code).

`~/.mcp.json` / `~/.codex/config.toml` point at it: `"command": "node", "args": ["~/.local/bin/demipass-pane-mcp.js"]`
(and `--buoy` for Buoy).

## What it does at start

1. **Credential.** Reads `DEMIPASS_TOKEN` (or `BUOY_TOKEN`) and the URL from `~/.mcp.json`'s matching server entry into
   its own environment. The credential is never copied into another config, printed, or written to the receipt.
2. **Conduit gate.** Conduit is enabled only if `~/.config/demipass/conduit.json` belongs to the same wallet as that
   credential. A missing, unreadable or other-wallet file disables **Conduit only** (one stderr line naming the file,
   never its content); vault, ssh and `/use` keep working.
3. **Pane identity** (DemiPass role only). Inherited `CONDUIT_MODEL_FAMILY` / `CONDUIT_SESSION_ID` / `CONDUIT_AUTOBIND`
   are discarded: the launcher is the only source. `CONDUIT_REQUIRE_PANE=1` is always set, so with no identity Conduit
   messaging fails closed instead of using the shared legacy name. It then walks up the parent chain (24 hops max) to
   the **nearest** agent runtime (`claude`, Claude Code's `cli.js`, `codex`, `~/.codex/packages/…`):
   - **Explicit binding.** A process on the way whose pid **and** start time (`/proc/<pid>/stat` field 22) match an
     entry in `~/.config/demipass/pane-bindings.json` gives `CONDUIT_MODEL_FAMILY` / `CONDUIT_SESSION_ID`. A reused
     pid never matches a stale entry.
   - **Autobind (Claude Code).** If the nearest agent has no binding and is Claude Code, `CONDUIT_AUTOBIND=claude` is
     set. The launcher does not guess a family; the SDK derives it (below). Refused when the session id is one the
     Claude process itself inherited (a `claude` started inside another pane that did not set its own), or when that
     process's environment cannot be read.
   - **Codex** (and any other runtime) stays unbound: Codex runs MCP servers under a shared app-server daemon with no
     per-session id, so there is nothing reliable to bind to. Bind such a pane explicitly with
     `conduit_onboard({model_family, session_id})` (or a `pane-bindings.json` entry).
   - The walk stops at the nearest agent, so a nested agent never takes its parent pane's address.
4. **Receipt.** `~/.config/demipass/runtime/pid-<pid>.json` (0600, directory 0700): pid, parent, role, model_family,
   session_id, autobind, runtime, unbound_reason, source, release, time. No credential.
5. **Load** `~/.local/share/demipass/releases/<sha>/mcp-server.js` (or `buoy-mcp.js`) in-process.

## Autobind in the SDK (`CONDUIT_AUTOBIND=claude`)

Claude Code gives MCP children `CLAUDE_CODE_SESSION_ID` (the session at MCP spawn) but no model variable. The model is in
the session transcript, `~/.claude/projects/<slug>/<session-id>.jsonl`, as `message.model` on assistant records.

At the **first Conduit call** (not at startup) `_conduitPane()`:

1. requires `CLAUDE_CODE_SESSION_ID` to be a full lowercase UUID **before** any path is built;
2. looks for `<sid>.jsonl` in each real directory under `~/.claude/projects/` (symlinked project directories are
   skipped); opens it with `O_NOFOLLOW` (a symlinked transcript is refused) and requires a regular file owned by this
   user; with several, the most recently modified wins;
3. reads only the last 512 KiB, drops the cut first line, and scans backwards for the last assistant record that is not
   a sidechain and whose model is `claude-<family>-…` (`<synthetic>` and other strings are skipped);
4. validates the family against `^[a-z][a-z0-9]{0,14}$` and binds `<family>-<sid>`.

Only the model string is taken; transcript content is never logged or returned.

- **Cached once resolved.** The address is fixed for the life of that MCP process. A later `/model` switch does **not**
  change it; a new address needs a new MCP process (restart or `/mcp`).
- **Not resolvable yet** (no transcript or no assistant record yet, as in a brand-new session at MCP spawn): the call
  reports `pane_error: "pane identity not resolvable yet: no model recorded for this session …"`, messaging is refused,
  and the next attempt (after 2 s) reads again. The model has normally replied by the time it calls a Conduit tool.
- **Precedence.** A pane already in use by this process → `CONDUIT_MODEL_FAMILY`/`CONDUIT_SESSION_ID` (explicit
  binding) → `CONDUIT_AUTOBIND`. An explicit `conduit_onboard({model_family, session_id})` made before the autobind has
  resolved takes precedence and is used as-is; once a pane is in use, a different one is refused.
- `conduit_status` / `conduitConfig()` report `pane_address` and `pane_source` (`env`, `autobind`, `onboard`), or
  `pane_error`.
- Users who move `~/.claude` with `CLAUDE_CONFIG_DIR` are not searched; bind those panes explicitly.
