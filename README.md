# DemiPass

> Secrets management for LLM sessions. Keep credentials out of context windows.

DemiPass lets AI agents use API keys, passwords, and tokens without ever seeing them. The secret is injected server-side at the point of use. The LLM context window never contains the credential.

## The Problem

Every Claude Code session, every GPT agent, every LangChain pipeline that manages infrastructure has secrets pasted into context. This means:
- Secrets in prompt logs
- Secrets potentially in training data
- Secrets visible to anyone with session access
- Violation of every enterprise secret management policy

## The Solution

```javascript
const demipass = require('demipass');

demipass.configure({
  baseUrl: 'https://api.dustforge.com',
  bearerToken: 'your-token',
});

// Store a secret (carbon/operator does this once)
await demipass.store({ name: 'OPENROUTER_KEY', value: 'sk-or-...' });

// Use it without seeing it (silicon/agent does this)
const { token } = await demipass.requestToken({ secretName: 'OPENROUTER_KEY' });
const result = await demipass.execute({ token, action: 'inject_env' });
// result contains the API response. The secret never entered this context.
```

## How It Works

1. **Carbon deposits** a secret into the DemiVault (encrypted at rest, AES-256-GCM)
2. **Silicon requests** a use-token by presenting its intended context (action type, target URL)
3. **DemiPass validates** the context against approved patterns
4. **Use-token issued** — 30-second, single-use, cryptographic nonce
5. **Silicon redeems** the token — DemiPass injects the secret server-side
6. **Result returned** — secret redacted from all output

The secret never enters the LLM context window at any step.

## Install

```bash
npm install demipass
```

## MCP Server (Claude Code)

Add to your Claude Code MCP config:

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
    }
  }
}
```

Exposes tools to Claude Code:
- `demipass_store` — store a secret (value never enters context)
- `demipass_get_token` — request a 30s use-token for a secret
- `demipass_execute` — redeem a use-token (secret injected server-side)
- `demipass_list` — list secret names (never values)
- `demipass_rotate` — rotate a secret with context transfer
- `demipass_onboard` — full onboarding via invite key flow

## Features

- **Use-tokens** — 30-second single-use nonces. The secret and the authorization are separate.
- **Context binding** — secrets can only be used for pre-approved actions on pre-approved targets
- **Delegation** — one agent authorizes another to use its secret without seeing it
- **Secret rotation** — new version auto-inherits contexts, old version enters grace period
- **7 action types** — http_header, http_body, ssh_exec, git_clone, smtp_auth, database_connect, env_inject (disabled)
- **Bonded Courier (Rowen)** — optional clean-room intermediary for high-security operations
- **Host whitelist** — secrets can only be sent to known, approved API providers
- **Audit trail** — every store, token issuance, delegation, and use is logged

## Architecture

```
Carbon (human) deposits secret → DemiVault (encrypted at rest)
                                      ↓
Silicon (agent) requests use-token → Context validation → 30s nonce issued
                                      ↓
Silicon redeems use-token → Secret injected server-side → Result returned
                                      ↓
                              Token burned → Audit logged
```

## Security Model: The Bonded Courier

- **Conductor** = dispatch desk (coordinates, never touches raw secrets)
- **Rowen** = bonded courier (chain of custody, not content inspection)
- **DemiPass** = identity verification at the door

We do NOT claim hardware-equivalent isolation. We claim process boundary separation with auditable custody chain. See [security-stance.md](docs/security-stance.md).

## License

MIT — AKStrapped LLC
