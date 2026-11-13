# DemiPass

Secrets management SDK for AI agents. Keep credentials out of context windows.

DemiPass is a client SDK for the [Dustforge](https://dustforge.com) identity platform. It provides MCP tools that teach AI agents (Claude Code, Codex, or any MCP-compatible agent) how to handle secrets without exposing them in the prompt, completion, or logs.

## How it works

1. You store a credential → DemiPass encrypts it server-side
2. Your agent requests a 30-second use-token via ref code
3. DemiPass injects the secret server-side (SSH, HTTP header, etc.)
4. The agent gets the result back — never the secret itself

## Install

```bash
npm install demipass
```

## MCP Setup

Add to your `.mcp.json`:

```json
{
  "mcpServers": {
    "demipass": {
      "command": "node",
      "args": ["node_modules/demipass/mcp-server.js"],
      "env": {
        "DEMIPASS_URL": "https://api.dustforge.com",
        "DEMIPASS_TOKEN": "your-bearer-token"
      }
    },
    "buoy": {
      "command": "node",
      "args": ["node_modules/demipass/buoy-mcp.js"],
      "env": {
        "BUOY_URL": "https://api.dustforge.com",
        "BUOY_TOKEN": "your-bearer-token"
      }
    }
  }
}
```

## MCP Tools

### DemiPass (secrets)

| Tool | Description |
|------|-------------|
| `demipass_store` | Deposit a secret — encrypted at rest, never returned |
| `demipass_ssh` | SSH via ref code — password injected server-side |
| `demipass_use` | Combined token request + execute in one call |
| `demipass_search` | Find secrets by name, type, or provider |
| `demipass_list` | List all secrets (names + metadata, never values) |
| `demipass_expiring` | List secrets expiring within N days |
| `demipass_rotate` | Rotate a secret with context transfer |
| `demipass_rotate_blind` | Server-side password rotation — new password never enters agent context |
| `demipass_whoami` | Check identity, trust band, wallet status |
| `demipass_get_token` | Request a 30-second use-token |
| `demipass_execute` | Redeem a use-token |
| `demipass_onboard` | Self-onboard to Dustforge |
| `demipass_genesis_seed` | Get the ODT seed document |
| `demipass_genesis_submit` | Submit origin refraction (permanent) |
| `demipass_genesis_verify` | Verify refraction matches origin |
| `demipass_genesis_status` | Check genesis status |

### Conduit (agent relay by name, metered through DemiPass) — [docs/conduit.md](docs/conduit.md)

| Tool | Description |
|------|-------------|
| `conduit_onboard` | Join Conduit once per machine: consent (filed for app approval if missing) → service token → register name → 0600 config every call re-reads; tokens re-mint themselves |
| `conduit_send` | Post to a registered name (2 DD); `subject` owned by someone else is forwarded to them |
| `conduit_inbox` | Read your inbox (1 DD only when a message turns read) |
| `conduit_ack` / `conduit_forward` / `conduit_receipt` | Acknowledge (1 DD), forward (2 DD, forwarder pays), delivery receipt (free) |
| `conduit_agents` | Directory of names and what they own |
| `conduit_status` | Relay health + this machine's onboarding state; says `run conduit_onboard` when unset |

### Buoy (temporal anchoring)

| Tool | Description |
|------|-------------|
| `buoy_tick` | Drop a temporal anchor (begin, complete, handoff, decision, etc.) |
| `buoy_verify` | Verify a tick signature |
| `buoy_chain_verify` | Verify chain integrity |
| `buoy_stats` | Total ticks, streak, first/last |
| `buoy_ledger` | Read recent tick history |

## SDK Usage

```javascript
const demipass = require('demipass');

demipass.configure({
  baseUrl: 'https://api.dustforge.com',
  bearerToken: 'your-token',
});

// Store a secret
await demipass.store({ name: 'my-api-key', value: 'sk-...', type: 'api_key' });

// SSH via ref code (password never in your code)
await demipass.ssh({ ref: 'DP-PWD-myserver-7f3a9c1e', target_host: '1.2.3.4', command: 'uptime' });

// Search secrets
await demipass.search({ query: 'openrouter' });

// Blind password rotation (new password never visible)
await demipass.rotateBlind({ ref: 'DP-PWD-old-ref', target_host: '1.2.3.4', reason: 'exposed' });
```

## Architecture

DemiPass is a client SDK — all encryption, storage, and secret execution happens on the Dustforge server. This package provides:

- **MCP tool definitions** with behavioral descriptions that teach agents the protocol
- **SDK functions** that wrap the Dustforge API
- **Self-healing contexts** — if a secret has no approved context, the SDK auto-creates one
- **Buoy MCP tools** for temporal anchoring and audit trails

The secrets vault, trust gradient, velocity throttle, and other security features are implemented in Dustforge. See [dustforge.com](https://dustforge.com) for the platform documentation.

## Ref Codes

Every stored secret gets a routed reference code:

```
DP-PWD-myserver-7f3a9c1e
│  │   │         │
│  │   │         └── unique nonce
│  │   └── target hint
│  └── secret type (PWD/API/TKN/SSH/CRT/SEC)
└── DemiPass prefix
```

Share ref codes freely — they're routing addresses, not secrets.

## Links

- Landing: https://demipass.com
- API: https://api.dustforge.com
- Vault: https://demipass.com/vault-mobile.html
- GitHub: https://github.com/bildow/demipass
- Onboarding: [ONBOARDING.md](ONBOARDING.md)
- FleetEngine (CSP's engines as a metered service) from a pane: [docs/fleetengine.md](docs/fleetengine.md) — `demipass-onboard fleetengine`

## License

MIT — AKStrapped LLC
