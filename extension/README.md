# DemiPass browser extension (Chromium, Manifest V3)

Puts passwords and API keys into a DemiPass vault without the value passing
through a clipboard, chat, terminal or transcript, and fills logins after the
person approves each fill on their phone with the vault PIN.

API contract: [`docs/browser-fill-api.md` on dustforge `feat/browser-fill`](https://github.com/bildow/dustforge/blob/feat/browser-fill/docs/browser-fill-api.md).
The fill, candidates and origins endpoints are **not deployed yet**. Until
they are, use the local mock (below).

## What it does

| Flow | How |
|---|---|
| Pair | Popup → **Pair with DemiPass** → device flow with `scope: 'transact'`. The popup shows the user code and a link to `https://demipass.com/device`. |
| Store selected text | Right-click a selection → **Store in DemiPass**. The browser hands the selection to the background worker. A small extension window asks for a name and type (`api_key`, `oauth_token`, `password`, `other`) and can optionally bind it to the page's origin. |
| Save a login on submit | The content script sees a login form submit and passes the username and password straight to the worker. The worker holds them in memory for 3 minutes and shows **SAVE** on the toolbar badge. The popup offers **Save to DemiPass**: `secret_type: 'password'`, `login`, `origins: [page origin]`. Nothing is stored unless the person clicks Save. |
| Fill | The popup lists the vault entries bound to the page's origin (`/fill/candidates`). **Fill** → `/fill/request` → "Approve on your phone…" → polls `/fill/redeem` (428/403/410/200). On 200 the worker re-checks the frame, injects the fill into that exact document, then drops the value. |
| Add for this site | Popup form (name, username, password), stored bound to the top frame's origin. |
| Sign out | Revokes the refresh token (`/api/identity/refresh/revoke`), revokes the access token by `jti` (best effort), and clears both from storage. |

## Security model

- **Only the background service worker talks to the API and holds tokens.**
  Content scripts hold no token. They send two kinds of message:
  "this frame has a login form" (no values), and the submit-time capture.
  The worker accepts `ui:*` messages only from extension pages and `dp:*`
  messages only from content scripts. It tells them apart by the
  browser-populated `MessageSender`.
- **The fill origin comes from the browser, never from the page.** The worker
  records each document's `sender.origin`, `sender.frameId` and
  `sender.documentId`, all set by the browser. The fill is requested for that
  origin. At fill time:
  1. The poll stops, and the request is never redeemed, if that document is
     gone or the tab navigated.
  2. The redeem response's `origin`/`ref` must equal what was requested.
  3. The worker re-checks its own record of the document.
  4. `chrome.scripting.executeScript` targets `documentIds: [documentId]`.
     That is stricter than `frameIds`: a navigated frame has a new document
     and the injection fails.
  5. The injected function checks `location.origin` against the approved
     origin in the same task as the write, so nothing can navigate between
     the check and the fill.
- **Values:** never logged, never written to storage, never put in a badge,
  title, notification or error message, and never sent to the popup. A
  pending save lives only in worker memory, with a 3-minute TTL. A fill value
  lives in one local variable and is nulled after injection.
- **Worker lifetime:** while a save, pairing or fill is in flight, the worker
  makes a cheap extension API call every 20 s so Chromium does not stop it
  (and drop the in-memory save) before the TTL. It stops when nothing is
  pending.
- **Tokens:**
  - The access token is in `chrome.storage.session`: memory only, trusted
    contexts only.
  - The refresh token is in `chrome.storage.local`, sealed with AES-GCM under
    a non-extractable key kept in the extension's own IndexedDB. Content
    scripts can read `chrome.storage.local` by default, but they cannot open
    the extension origin's IndexedDB.
  - Refresh rotates the pair. It is single-flight, because the refresh token
    is single-use, and the new refresh token is persisted before the new
    access token is used.
  - A carbon fill request belongs to the one access token (`jti`) that made
    it; a refreshed token gets 404 on redeem. So before `/fill/request` the
    worker refreshes if the access token expires within 5 minutes. If a
    refresh happens anyway while the request waits (or redeem answers 404),
    it asks once more and the popup shows "Approve on your phone…" again.
  - A 401, or dustforge's 403 `admin access or Bearer token required` (what
    `getDemiPassActor` returns for a bad bearer when `ADMIN_API_KEY` is set),
    triggers one refresh and one retry. A 403 `denied` from redeem does not.
- **Origins:** `https` anywhere. Plain `http` only for `localhost` and
  `127.0.0.1`. Matching is exact.
- **The capture UI is the extension popup, not page DOM**, so the page cannot
  script it.
- No remote code, no dependencies, no build step. Extension pages run under
  `script-src 'self'; object-src 'none'`.

What it does not protect against is the same as in the contract. Whatever the
value is filled into can read it, and so can anything that drives the browser
(DevTools/CDP).

## Permissions

| Permission | Why |
|---|---|
| `storage` | Access token in `storage.session`; sealed refresh token and the optional dev-server setting in `storage.local`. |
| `contextMenus` | The **Store in DemiPass** item on selected text. |
| `scripting` | The fill: `executeScript` into the exact document after approval. Also injects the detector into tabs opened before install. |
| `activeTab` | Grants `scripting` on the tab when the person clicks the toolbar button (or uses the context menu), so no broad host permission is needed for filling. |
| `host_permissions: https://api.dustforge.com/*` | The worker's API calls. |
| content script on `<all_urls>`, all frames | Login-form detection and the submit capture. It reads password fields only at submit, and only to hand the value to the worker. |

`webNavigation` is **not** requested. The browser-set `MessageSender` fields
plus `documentIds` targeting and the in-frame check give a tighter origin
guarantee than a separate `getFrame` lookup. A lookup would also have a gap
between the check and the injection, and the permission adds a "read your
browsing history" warning.

## Limits

- Filling a **cross-origin iframe** (e.g. an embedded login on another domain)
  needs host permission for that origin. `activeTab` covers only the tab's
  top-level origin, so those fills fail with "Could not reach the page".
- The submit capture covers native submits, clicks on sign-in buttons, and
  Enter in a form-less password field. Multi-step logins that ask for the
  username and password on separate pages capture only the password page's
  fields, so the username may be empty. The person can still save.
- Selection text is whatever Chromium reports as `selectionText`, trimmed.
- No icons yet. Chromium shows its default.

## Develop and test

Load unpacked: `chrome://extensions` → Developer mode → **Load unpacked** →
choose this `extension/` directory.

Use the local mock instead of production:

```sh
node extension/test/mock-server.js 8787 8788
# then in the extension's options: API server = http://127.0.0.1:8787
# test site: http://localhost:8788/login.html (and http://127.0.0.1:8788 as a second origin)
```

The options page accepts only `https://api.dustforge.com` or a `localhost` /
`127.0.0.1` server. The popup shows a banner while a dev server is in use.

Tests:

```sh
npm run test:extension        # node:test unit tests (origin, form detection, API state machine, refresh, mock round trip)
PLAYWRIGHT_CORE=/path/to/node_modules/playwright-core npm run test:extension:e2e
```

The smoke test loads the unpacked extension in Playwright's Chromium (headless)
against the mock server and a local login page. The copy it loads gets
`http://localhost/*` and `http://127.0.0.1/*` host permissions. That is the one
test-only change: headless Chromium cannot click the toolbar button that
grants `activeTab`.
