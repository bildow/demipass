# Agent browser fill (flight 3)

An agent that drives a browser logs in to a website with a login from the DemiPass vault, and the value never
enters the model's context, tool results, transcript, logs or terminal pane. The agent says "fill the login on
this page with DP-PWD-…"; the tool gets the value from DemiPass, puts it into the page, and returns
`{filled: true, chars: N, origin}`.

Server contract: `docs/browser-fill-api.md` on dustforge branch `feat/browser-fill` (**not deployed** as of
2026-10-25). The agent authenticates with a silicon token. A silicon that holds `action:browser_fill` on the
secret gets its request approved at once. A carbon token waits for PIN approval on the phone (`wait_seconds`,
`request_id` to resume).

## Paths

| Browser the agent drives | Use | Why |
|---|---|---|
| Chromium over CDP (Playwright, puppeteer, `--remote-debugging-port`) | `demipass_browser_fill {ref, cdp_url?, target_id?}` in `mcp-server.js` | Chromium shows every page to every CDP client, so a second client can attach to the agent's page. |
| Lightpanda through goose (`lightpanda mcp`, stdio) | `browser-fill/lightpanda-mcp.js`, the wrapper MCP server, in place of `lightpanda mcp` | Nothing outside the MCP process can reach its page (see below). |
| Lightpanda `serve` driven by puppeteer/Playwright | `fillOnSession(send, …)` from `browser-fill/cdp-fill.js`, on the driver's own CDP session | `serve` gives every CDP connection its own browser. |

### Which DevTools endpoint (Chromium path)

The page origin, and so which login the server releases, is whatever the DevTools endpoint reports. An endpoint
the agent may name freely is an exfiltration path: a prompt-injected agent passes `cdp_url` of a fake endpoint that
claims its page is `https://bank.example`, the server approves bank.example's login, and the value arrives at the
fake in `Runtime.callFunctionOn`. So:

- **`DEMIPASS_CDP_URL` set (operator config):** it is the only endpoint. A `cdp_url` argument that differs is refused (`cdp_url_not_allowed`). The advertised `webSocketDebuggerUrl` must be on the same host or on loopback.
- **Not set:** the agent's `cdp_url` must be a literal loopback address (`127.0.0.0/8` or `[::1]`; not a name, not even `localhost`, so no DNS answer decides it), and so must the `webSocketDebuggerUrl` that `/json/version` advertises (`cdp_not_loopback`). `/json/version` redirects are not followed.

What remains: **any process of the same uid (or any local user, if the port is not otherwise guarded) that listens
on loopback can pose as the browser.** Loopback narrows the attack to local code, which already has the same-uid
reach described below; it does not authenticate the browser. Where that matters, set `DEMIPASS_CDP_URL` to the
browser the operator launched.

Shared pieces:
- `browser-fill/fill-core.js`: the origin rules (the same as the server), request/redeem with 428 polling, value-free `FillError`, and the `Redactor`.
- `browser-fill/page-script.js`: field detection and the fill itself, run in the page.

## Lightpanda 1.0.1: can a second client see goose's page?

**No.** Evidence:

- **Binary.** `https://github.com/lightpanda-io/browser/releases/download/1.0.1/lightpanda-x86_64-linux`, sha256
  `551747e35c51ba107b5d5277eca4b48e077b2a3b40f09a047bf6670448bc35fd`. This equals `LIGHTPANDA_SHA256` in boltcluster
  `fleet/image/versions.conf`. Local copy: `/home/flimflam/tmp/lightpanda-1.0.1/`. `version` prints `1.0.1`.
- **Fleet launch.** The `fleet/image/files/config.yaml` extension `lightpanda` is `type: stdio`, `cmd: /usr/local/bin/lightpanda`, `args: [mcp]`. `/usr/local/bin/lightpanda` is a shell shim around `glibc-run /opt/lightpanda/bin/lightpanda`.
- **The `mcp --cdp-port` flag.** `lightpanda help mcp` lists `--cdp-port <INT>`: "Also run a CDP (WebSocket) server on this port". It cannot be combined with `--port`.
- **Source, tag `1.0.1` (`99edca45`):**
  - `src/main.zig:258` creates the CDP server.
  - `mcpThread` (`:395`) takes it only to shut it down.
  - The MCP session is a `ToolSession` (`src/ToolSession.zig:19`: "its own Browser (hence V8 isolate), Session…").
  - CDP connections get their own browsers.
- **What I ran.**
  - `lightpanda mcp --cdp-port 9343`, MCP `goto` to a local login page, then a second client on `ws://127.0.0.1:9343/`. `Browser.getVersion` answers. `Target.getTargets` returns `targetInfos: []` before an MCP navigation, and after one it did not answer within 5 s.
  - `lightpanda serve`: client A creates a context and target and navigates. Client B's `Target.getTargets` is `[]`. This is also in the test suite.

So a CDP fill tool cannot reach the page goose is on. A wrapper around `lightpanda serve` could, but it would have to
re-implement Lightpanda's semantic MCP tools (tree, markdown, detectForms, findElement, extract…) over CDP. The chosen
design is a **transparent stdio proxy in front of `lightpanda mcp`**:

- It passes every message through unchanged.
- It adds `demipass_browser_fill` and `demipass_browser_fill_candidates`.
- It fills by calling Lightpanda's own `fill` tool with internal request ids. Those results go nowhere.

That last point matters:
- Lightpanda's `fill` result echoes the value: `Filled element (selector: #p) with "<value>"` (`src/browser/tools.zig:2178`).
- Action results carry the post-action page URL (`finalizeAction`), so a GET login form puts the password in a click result.

Both were reproduced with raw `lightpanda mcp`.

Other 1.0.1 facts that matter here:
- Lightpanda masks `input[type=password]` as `*****` in its LLM-facing dumps: tree, detectForms, interactiveElements and the AX tree (`Input.zig:155–160`, `getRedactedValue`). Page JavaScript (`evaluate`) still sees the raw value.
- Lightpanda has its own `$LP_*` substitution: env vars set when the browser starts. It is not used here, for three reasons:
  - The value would sit in the process environment for the whole session.
  - `getEnv {name}` returns it to the model on request.
  - It cannot fetch a DemiPass secret on demand.
- The screenshot renderer (`RenderTree.zig`) has no code path that draws input values. This is from reading the source, not from a rendered check.

### How a fill runs in the wrapper

1. `getUrl` gives the origin. Page script cannot set the origin.
2. Internal `evaluate` finds the fields and tags them `data-demipass-fill="<nonce>:u|p|s"`. No value is involved, so a page with no login form never spends a request.
3. `fill/request` + `fill/redeem`. The origin the server approved must equal the page origin.
4. `getUrl` again, then Lightpanda `fill` on the tagged selectors, which fires real input and change events. If the page navigated, the tags are gone and the fill fails closed.
5. Optional submit through `click` on the tagged submit button (or Enter).
6. After the password `fill`, an internal `evaluate` reads the field's length. If the field holds a different number of characters than the value (a length guard, a page script):
   - What the field holds is read (internal `evaluate`, never forwarded) and added to the Redactor: it derives from the value, and page JS may keep a copy.
   - The field is emptied with Lightpanda `fill ''` (events, so page state follows), then, if the page refilled it, with the native setter and no events. Emptiness is re-checked.
   - Emptied → `value_not_accepted`. Still not empty → `clear_failed` ("part of the value may still be in the field"); what it holds is redacted from later results unless under 4 characters.
   The Chromium path does the same two-step clear in the page and reports `clear_failed` the same way (nothing is scrubbed there; see below). On success `chars` is the measured length.
7. From then on, Lightpanda results and stderr lines are scrubbed, best-effort, of the value where they echo it as-is or in one of the encodings in `fill-core.js` (`encodingVariants`): JSON; `encodeURIComponent`, with `+` spaces, with `'` → `%27` (how the URL parser re-serializes an encoded href in links / interactiveElements / extract), and strict RFC 3986; form encoding; a form query passed through `decodeURIComponent` (spaces left as `+`); a raw value in a parsed query; HTML escapes `&<>"'` / `&<>"` / `&<>` (text nodes leave quotes raw); markdown backslash escapes ``\`*_{}[]()#+-!|``; lowercase-hex percent forms; and the JSON string body of each. Anything transformed another way is not caught.

Protocol details of the proxy:
- **Ids.** Every request Lightpanda sees carries an id the proxy minted. Agent ids are rewritten on the way in and restored on the way out; internal calls use ids from the same counter; a reply to an id the proxy did not mint for the agent is dropped. An agent id can never be taken for an internal reply, and an internal reply can never reach the agent. `notifications/cancelled` is mapped to the minted id. JSON-RPC batches are refused.
- **Holding.** Agent requests are held while a fill tool runs and until every internal call has been answered. A call that times out (30 s) fails the fill, but its id stays registered, so agent requests stay held until Lightpanda answers it, and the late reply is swallowed. Still unanswered 60 s after the timeout (a page stuck in `while (true)`), Lightpanda is killed and every held request is answered "the browser exited".
- **DemiPass HTTP calls** (candidates, request, each redeem poll) have a 15 s deadline per call (`configure({ fillTimeoutMs })`), mapped to the `network` error. An approval wait is many short polls, so `wait_seconds` is not capped by it.
- **Lightpanda exits.** A fill running at that moment still answers (`browser_gone`) before the wrapper exits with Lightpanda's code.
- **`tools/list`.** Child tools named `demipass_*` are dropped; the fill tools are added to the first page only (no `cursor`).

### goose config (proposed — not applied to the fleet)

```yaml
  lightpanda:
    enabled: true
    type: stdio
    name: lightpanda
    cmd: /usr/local/bin/demipass-lightpanda-mcp       # node …/browser-fill/lightpanda-mcp.js
    args: [--lightpanda, /usr/local/bin/lightpanda]   # extra lightpanda mcp args after `--`
    envs:
      DEMIPASS_URL: https://api.dustforge.com
      DEMIPASS_FILL_TOKEN_FILE: /etc/agent-fill/demipass-fill.token   # silicon token, 0600, from fleet/agent-provision
    timeout: 120
```

- **Fill identity.** The token is read on every fill call. While `DEMIPASS_FILL_TOKEN_FILE` names a file that is absent (the image before provisioning), unreadable or empty, or `DEMIPASS_FILL_TOKEN` is set but blank, the fill tools answer `no_fill_identity` ("no fill identity provisioned") and make no request; the Lightpanda tools keep working. A configured-but-unusable fill identity never falls back to `DEMIPASS_TOKEN` or the credentials file. Only with neither variable set does the wrapper use the usual bearer.
- **No `X-Admin-Key`** is sent with fill requests (SDK `fillCandidates` / `fillRequest` / `fillRedeem`), even when `DEMIPASS_ADMIN_KEY` is configured.
- **No dotenv.** The wrapper does not load `dotenv`: an optional `require('dotenv')` resolves through `~/.node_modules` and the like, which the agent's uid can write, and would run that code inside the process that holds fill values. Configuration comes from the extension's `envs` only.
- **Runtime files.** The wrapper requires only `index.js`, `browser-fill/lightpanda-mcp.js`, `browser-fill/fill-core.js`, `browser-fill/page-script.js` and Node core modules. (`index.js` requires `./package.json` lazily, inside `doctor()` only, which the wrapper never calls.)

The image needs Node in this setup: `apk add nodejs`. The wrapper uses only `child_process`, `crypto` and `http(s)`,
so it needs no npm dependencies and no global WebSocket. That is an F1 image change, not made here; the Node version
Alpine 3.24 ships was not checked.

## What this does not protect

- **Whatever drives the browser can read a filled field.** That is the page, and anything with CDP or `evaluate`. This is leak prevention: the value does not land in the model's context or logs by accident. It does not contain a hostile agent. The Chromium test asserts the agent's own driver can read the field's length.
- **The Redactor is best-effort scrubbing of values the page echoes. It catches accidents, not intent.**
  - It replaces only the value as-is and the encodings listed above. A page or agent that transforms the value any other way (base64, slicing, char codes, another escaping scheme) gets it through, and so does a substring.
  - An agent that reads the field through `evaluate` and transforms it gets the transformed value.
  - Values under 4 characters are not scrubbed.
  - In the Chromium path nothing is scrubbed after the call: the agent's own Playwright or CDP client is not ours to filter.
- **Same uid means no boundary.** In the fleet, goose's `developer` extension (a shell) runs as the same user as the wrapper. It can read the token file and `/proc/<pid>/environ`, then call `fill/request` + `fill/redeem` itself and get the raw value, or listen on loopback and pose as the DevTools endpoint (see "Which DevTools endpoint"). The silicon grant is the real boundary.
  - Keep grants per secret (never `*` for agents).
  - Use the server's events (`secret_filled`, `fill_blocked_silicon`) to audit.
  - For containment, run the wrapper under its own uid with the token file readable only by that uid. That needs a privileged launcher in the image.
- **A fill hands the site a session.** After login, `getCookies` returns session cookies to the agent, and `--cookie-jar` writes them to disk. Those are credentials too. Out of scope here.
- **Main frame only.** A login form inside an iframe (cross-origin OOPIF in Chromium, `--load-resources iframe` in Lightpanda) is not filled.
- **Multi-step logins.** A page that shows the username first and the password on a later page needs one fill per page. Each fill spends one request; a page with no password field is refused before a request is made.
- **`$LP_` collision.** A stored value that contains `$LP_NAME`, where `LP_NAME` is set in the browser's environment, would be substituted by Lightpanda. The wrapper refuses such a fill (`value_needs_escape`).
- **The approved origin is checked twice.** Once before the value is requested, and again in the same JS task that sets the value (Chromium) or through the document-bound tags (Lightpanda). A page that navigates by script right after the fill can still send the value wherever its own JS wants. The page holds the value at that point.
- **Origin rules follow the server:**
  - `https:` everywhere, plain `http:` only on localhost or 127.0.0.1.
  - Exact match: `localhost` and `127.0.0.1` are different origins, and the tests use that.

## Tests

`node test/browser-fill.test.js` (also part of `npm test`) uses a mock fill server that implements the contract and
a local login site. It covers:
- The fill lands in the right fields: the site receives the exact values, from a form post and from a framework-style page that reads JS state set by input events.
- Origin mismatch is refused both ways: an unbound origin gets 403, and a server that approves another origin is refused by the client.
- 403 (not granted, denied), 410 (expired, already redeemed) and 428 (`approval_pending` + resume).
- No or ambiguous password field is refused before a request is made.
- Several pages open: `ambiguous_page`, then `target_id` picks one.
- In the Lightpanda wrapper, an agent reading the field back gets `[demipass:redacted]`, and so does a GET form's URL. A page that echoes the value (text, title, link href, input value, console) is read back through markdown, links, interactiveElements, html, extract and `decodeURIComponent(location.search)`; no encoding of the value may appear. The Redactor is also checked against literal strings captured from Lightpanda 1.0.1.
- The DevTools endpoint: non-loopback `cdp_url`, a loopback endpoint advertising a WebSocket elsewhere, a redirecting `/json/version`, and a `cdp_url` that differs from `DEMIPASS_CDP_URL` are refused with no request spent; with `DEMIPASS_CDP_URL` set a fill needs no `cdp_url`.
- Fill identity: a missing/unreadable/empty token file or a blank token refuses (`no_fill_identity`) even with a working `DEMIPASS_TOKEN`, in `mcp-server.js` and the wrapper; provisioning the file later makes the next fill work. No fill request carries `X-Admin-Key`. A planted `~/.node_modules/dotenv` never runs in the wrapper.
- Wrapper protocol, against a scripted Lightpanda (`test/fake-lightpanda-mcp.js`): agent ids equal to the ids the proxy mints next get their own replies; after an internal timeout, agent requests stay held until Lightpanda answers and the late reply (which echoes the value) never reaches the agent; a field that keeps fewer characters is cleared (`value_not_accepted`, also on real Chromium and Lightpanda); `tools/list` pagination; a 32 MiB reply passes intact, and line framing is linear.
- **Leak check.** Every MCP stdout line the agent receives, every stderr line, and every log line is searched for the value and its encodings. A positive control proves the detector catches each encoding.

Browsers: Chromium (`CHROMIUM_BIN`, else the Playwright cache) and Lightpanda (`LIGHTPANDA_BIN`, else
`/home/flimflam/tmp/lightpanda-1.0.1/lightpanda-x86_64-linux`). A missing browser is reported as SKIPPED.
