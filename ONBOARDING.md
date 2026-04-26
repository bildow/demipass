# DemiPass + Buoy — Agent Onboarding

Works with any LLM agent that supports MCP (Claude Code, Codex, or custom).

## 1. Install

```bash
npm install demipass
```

## 2. Add MCP servers

Add to your `.mcp.json` (project root) or agent MCP config:

```json
{
  "mcpServers": {
    "demipass": {
      "command": "node",
      "args": ["node_modules/demipass/mcp-server.js"],
      "env": {
        "DEMIPASS_URL": "https://api.dustforge.com",
        "DEMIPASS_TOKEN": ""
      }
    },
    "buoy": {
      "command": "node",
      "args": ["node_modules/demipass/buoy-mcp.js"],
      "env": {
        "BUOY_URL": "https://api.dustforge.com",
        "BUOY_TOKEN": ""
      }
    }
  }
}
```

### Codex CLI

Codex uses `~/.codex/config.toml`, not `.mcp.json`. Run these commands:

```bash
codex mcp add demipass -- node node_modules/demipass/mcp-server.js
codex mcp add buoy -- node node_modules/demipass/buoy-mcp.js
```

Then add env vars to `~/.codex/config.toml`:

```toml
[mcp_servers.demipass.env]
DEMIPASS_URL = "https://api.dustforge.com"
DEMIPASS_TOKEN = "your-bearer-token"

[mcp_servers.buoy.env]
BUOY_URL = "https://api.dustforge.com"
BUOY_TOKEN = "your-bearer-token"
```

**Important:** Codex must be fully restarted (not just session resumed) after adding MCP servers. The tools are loaded at launch time.

### Other MCP-compatible agents

If your agent framework uses a different MCP config format, the key information is:
- MCP server command: `node node_modules/demipass/mcp-server.js`
- Required env: `DEMIPASS_URL` + `DEMIPASS_TOKEN`
- Optional env: `CONDUIT_URL` + `CONDUIT_TOKEN` + `CONDUIT_SENDER`
- First tool to call: `demipass_doctor` — reports identity, API status, secrets, and recommendations

## 3. Get an identity

Option A — self-onboard (agent does it):
- Use the `demipass_onboard` tool with a username
- The agent gets a DID, email, wallet, and referral code
- The invite key serves as the initial password

Option B — carbon provisions (human does it):
```bash
curl -s -X POST https://api.dustforge.com/api/identity/request-invite \
  -H 'Content-Type: application/json' -d '{}'
# Use the returned key to create an account for your agent
```

## 4. Get a Bearer token

```bash
curl -s -X POST https://api.dustforge.com/api/identity/auth-fingerprint \
  -H 'Content-Type: application/json' \
  -d '{"username":"your-agent","password":"your-key","scope":"transact","expires_in":"30d"}'
```

Paste the returned `token` into `DEMIPASS_TOKEN` and `BUOY_TOKEN` in your MCP config.

## 5. Restart your agent

The agent now has these tools:

### DemiPass (secrets)
| Tool | What it does |
|------|-------------|
| `demipass_store` | Deposit a secret — encrypted, never returned |
| `demipass_ssh` | SSH via ref code — one call, password injected server-side |
| `demipass_use` | Combined token request + execute in one call |
| `demipass_search` | Find secrets by name/type/provider |
| `demipass_list` | List all secrets (names only, never values) |
| `demipass_expiring` | List secrets expiring within N days |
| `demipass_rotate` | Rotate a secret with context transfer |
| `demipass_whoami` | Check identity, trust band, wallet status |
| `demipass_get_token` | Request a 30-second use-token |
| `demipass_execute` | Redeem a use-token |
| `demipass_onboard` | Self-onboard to Dustforge |

### Buoy (temporal anchoring)
| Tool | What it does |
|------|-------------|
| `buoy_tick` | Drop a temporal anchor (begin, complete, handoff, decision, etc.) |
| `buoy_verify` | Verify a tick signature |
| `buoy_chain_verify` | Verify chain integrity for a tick range |
| `buoy_stats` | Total ticks, streak, first/last |
| `buoy_ledger` | Read recent tick history |

## How it works

**Secrets**: When your agent encounters a credential, it deposits it via `demipass_store`. The secret is encrypted at rest. When the agent needs the credential, it uses a ref code (e.g. `DP-PWD-myserver-7f3a9c1e`) to request a 30-second use-token. The secret is injected server-side — it never enters the agent's context window.

**Temporal anchoring**: The agent drops Buoy ticks at task boundaries. Each tick is chain-hashed to the previous one, creating a tamper-evident timeline. Signed ticks include a wallet attestation proving the agent has custody of real secrets.

## Ref codes

Every stored secret gets a routed reference code:

```
DP-PWD-myserver-7f3a9c1e
│  │   │         │
│  │   │         └── unique nonce
│  │   └── target hint
│  └── secret type (PWD/API/TKN/SSH/CRT/SEC)
└── DemiPass prefix
```

Share ref codes freely — they're routing addresses, not secrets. The agent uses them to request use-tokens. The secret is never exposed.

## Self-healing

If a secret has no approved context, the SDK auto-creates one scoped to the specific target host. The agent never sees "context not found" — it just works.

## Security

- Secrets encrypted at AES-256-GCM
- Use-tokens: 30-second, single-use
- Per-DID rate limiting (10 tokens/min)
- Velocity throttle (5 distinct secrets in 30 min = auto-suspend)
- Honeypot deception on exfiltration attempts
- Prompt injection filter on secret descriptions
- SSHPASS env var for SSH (never on command line)

## Links

- npm: https://www.npmjs.com/package/demipass
- Landing: https://demipass.com
- Vault: https://demipass.com/vault-mobile.html
- QR deposit: https://demipass.com/qr-deposit.html
- GitHub: https://github.com/bildow/demipass
- Buoy: https://buoy.dustforge.com
