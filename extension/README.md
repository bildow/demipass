# DemiPass browser extension (Chromium + Firefox, Manifest V3)

Puts passwords and API keys into a DemiPass vault without the value passing
through a clipboard, chat, terminal or transcript, and fills logins after the
person approves each fill on their phone with the vault PIN.

API contract: [`docs/browser-fill-api.md` on dustforge `feat/browser-fill`](https://github.com/bildow/dustforge/blob/feat/browser-fill/docs/browser-fill-api.md).
The fill, candidates and origins endpoints are **not deployed yet**. Until
they are, use the local mock (below).

One source tree runs in **Chrome, Brave** (and other Chromium browsers) and
**Firefox, Zen** (and other Gecko browsers). The code is identical. A small
build step (`build.mjs`, no dependencies) writes one manifest per family:

| | `dist/chromium/` | `dist/firefox/` |
|---|---|---|
| Background | `background.service_worker` (module service worker) | `background.scripts` (module event page; Firefox has no extension service worker) |
| Browser keys | `minimum_chrome_version: 116` | `browser_specific_settings.gecko`: id `demipass-browser@demipass.com`, `strict_min_version: 153.0`, `data_collection_permissions` |
| Everything else | same permissions, content scripts, popup, options, CSP | same |

One manifest carrying both `service_worker` and `scripts` would also load,
but `web-ext lint` flags `service_worker` (`BACKGROUND_SERVICE_WORKER_IGNORED`),
and each family would carry keys only the other reads. With two generated
manifests, `web-ext lint` on `dist/firefox` reports 0 errors, 0 warnings and
0 notices.

`strict_min_version: 153.0` is the first Firefox with
`MessageSender.documentId` and `scripting.executeScript({ target: { documentIds } })`.
It is also the current ESR. Zen follows Firefox release; Zen 1.23.4b is Gecko 158.

## Install

Build first: `npm run package:extension` (from the repo root). It writes
`extension/dist/chromium/`, `extension/dist/firefox/`,
`extension/dist/demipass-chromium-<version>.zip` and
`extension/dist/demipass-firefox-<version>.xpi`.

- **Chrome / Brave:** open `chrome://extensions` (Brave: `brave://extensions`),
  turn on Developer mode, click **Load unpacked**, and pick `extension/dist/chromium`.
  Loading `extension/` itself also works for Chromium.
- **Firefox / Zen (temporary):** open `about:debugging#/runtime/this-firefox`,
  click **Load Temporary Add-on…**, and pick `extension/dist/demipass-firefox-<version>.xpi`
  (or `dist/firefox/manifest.json`). It stays until the browser restarts.
- **Firefox / Zen (permanent):** release Firefox and Zen install only
  Mozilla-signed add-ons. That needs an AMO account and API keys, then
  `web-ext sign --channel=unlisted --source-dir extension/dist/firefox --api-key … --api-secret …`.
  An unlisted, self-distributed signed `.xpi` then installs like any other add-on.
  Whether to do this, and whose account to use, is the owner's call. Nothing
  here has been signed. The first signing fixes the gecko `id`, so change it
  before then if wanted. Firefox Developer Edition, Nightly and unbranded
  builds can instead set `xpinstall.signatures.required = false` and install
  the unsigned `.xpi`.
- **Firefox site access:** Firefox treats host access as the person's choice.
  A normal install asks for it. It can be turned off in `about:addons` →
  DemiPass → Permissions, or limited per site from the toolbar's extensions
  menu. When it is off for the current site, the popup says so and offers
  **Allow on this site** and **Allow on all sites**. The options page shows
  the all-sites state. Without site access, filling still works when the
  popup is opened from the toolbar (that grants `activeTab`), but the login
  form is not watched, so a typed login cannot be offered for saving.

## What it does

| Flow | How |
|---|---|
| Pair | Popup → **Pair with DemiPass** → device flow with `scope: 'transact'`. The popup shows the user code and a link to `https://demipass.com/device`. |
| Store selected text | Right-click a selection → **Store in DemiPass**. The browser hands the selection to the background worker. A small extension window asks for a name and type (`api_key`, `oauth_token`, `password`, `other`) and can optionally bind it to the page's origin. |
| Save a login on submit | When the person sends a login form (their own click or Enter), the content script passes the username and password straight to the worker, but only for a password the person put in the field themselves (see the security model). The worker holds them in memory for 3 minutes, one per frame, and shows **SAVE** on the toolbar badge. The popup offers **Save to DemiPass**: `secret_type: 'password'`, `login`, `origins: [page origin]`. Nothing is stored unless the person clicks Save. |
| Fill | The popup lists the vault entries bound to the page's origin (`/fill/candidates`). **Fill** → `/fill/request` → "Approve on your phone…" → polls `/fill/redeem` (428/403/410/200). On 200 the worker re-checks the frame, injects the fill into that exact document, then drops the value. |
| Add for this site | Popup form (name, username, password), stored bound to the origin the popup showed. It is refused if the tab is on another origin by the time of Add. |
| Rotated name | If the server answers 409 because the name was rotated ("…the current version is 'X_v2' — store under that name"), the whole message is kept. The captured value stays pending, and the button becomes **Save to “X_v2”**, which replaces the current version and adds this site to its origins. |
| Same name | Every save path checks `/api/blindkey/list` first, comparing the trimmed name. If the name exists, nothing is stored. The button turns into **Replace** and says what would be replaced. A confirmed replace stores without `origins`, which keeps the existing binding, then adds this page's origin with `/api/blindkey/origins` `mode: 'add'`. If that second step fails, the popup says exactly that: "Password replaced in “X”, but this site wasn't added to it. Try again." |
| Sign out | Revokes the refresh token (`/api/identity/refresh/revoke`), revokes the access token by `jti` (best effort), and clears both from storage. |

## Security model

- **Only the background talks to the API and holds tokens.** That is the
  service worker in Chromium and the event page in Firefox. Below, "worker"
  means either one.
  Content scripts hold no token. They send two kinds of message:
  "this frame has a login form" (no values), and the submit-time capture.
  The worker accepts `ui:*` messages only from extension pages and `dp:*`
  messages only from content scripts. It tells them apart by the
  browser-populated `MessageSender`.
- **The fill origin comes from the browser, never from the page.** The worker
  records each document's `sender.origin`, `sender.frameId` and
  `sender.documentId`, all set by the browser. Chromium has sent these since
  106. Firefox sends `origin` since 126 and `documentId` since 153. Where a
  browser leaves out `sender.origin`, the origin is taken from the
  browser-set `sender.url`. Either way it must equal the content script's
  own `location.origin`, so an opaque-origin frame (sandboxed, `about:blank`,
  `data:`) is never fillable. Each content script also makes a random
  128-bit nonce for its document, in its isolated world, where the page
  cannot read it. The fill is requested for that origin. At fill time:
  0. Before asking at all, the worker checks that it can script that frame
     and that the frame is still that document. If it cannot (no host
     access, for example a cross-origin frame in Chromium), the person gets
     the reason, and no card goes to the phone.
  1. The poll stops if the document is gone, and the request is then never
     redeemed. A document that unloads says so from `pagehide`, and before
     every redeem the worker asks the frame itself (same `documentIds`/nonce
     target as the fill) whether it is still that document on that origin.
     Same-document changes do not stop the poll: pushState, hash changes,
     and subframes loading. The fill still lands after the person approved
     it. (An earlier build dropped every record on Chromium's tab
     `status: 'loading'`, which fires for all of those.) A `pagehide` that
     the page dispatches itself (`isTrusted: false`) is ignored. A request
     the worker stops waiting for (page gone, cancelled, an error) is
     withdrawn with `POST /api/blindkey/fill/withdraw { request_id }`. Only
     the session that asked can do that, so another tab's request for the
     same login is never touched. The card leaves the phone, does not count
     toward the 20-waiting limit, and a later redeem answers 410 `withdrawn`.
     An expired request is not withdrawn, because it is over already. One
     orphaned by a token refresh belongs to the old token, so it is left to
     expire (120 s).
  2. The redeem response's `origin`/`ref` must equal what was requested.
  3. The worker re-checks its own record of the document.
  4. `scripting.executeScript` targets `documentIds: [documentId]`. That is
     stricter than `frameIds`: a navigated frame has a new document, and the
     injection fails. If a browser gives no `documentId`, the target is
     `frameIds: [frameId]`, and step 5 does the same job.
  5. In the same task as the write, the injected function checks that
     `location.origin` equals the approved origin and that the frame's
     document nonce is the one recorded. Nothing can navigate between the
     check and the fill. A reload or a navigation gives a new document,
     with a new nonce or none, and is refused ("The page changed before the
     fill; nothing was filled").
- **Save prompts come from the person's own typing and their own send.**
  The rules, in `content/content.js`:
  1. **One gesture, one edit.** A trusted keydown, paste or drop on a field
     issues one token for that field, valid until the end of the current
     task. The keydown must be a character, Backspace or Delete, without
     Ctrl/Meta. The next trusted `input` event on that field spends the
     token, and it counts only if it is the edit that gesture makes:
     - a character key K gives `inputType: 'insertText'` with `data === K`;
     - Backspace/Delete gives a delete;
     - paste gives `insertFromPaste`, and drop gives `insertFromDrop`.

     IME input counts while a trusted composition is open on the field. The
     page must also have transient user activation.
     `execCommand('insertText')` therefore never counts: not on its own, not
     from a timer, and not nested inside the person's own keystroke, where
     the token is already spent. Synthetic events and `.value` writes do not
     count either. An input that does not count marks the field as not the
     person's until they type in it again.
  2. **The value sent is the one the person left.** It is the field's value
     after its last counted input. If the page changed it since (swapped it
     before submit), nothing is offered.
  3. **Capture happens only on the person's own send.** That is a trusted
     click on a submit control or on any other button of the page that is
     not plainly something else (show/hide password, forgot, reset, cancel,
     back, clear, help, close, or a toggle with `aria-pressed`), labeled or
     not, in a form or not; or a trusted Enter in any field. `submit`
     events are not used, so `requestSubmit()` and `form.submit()` from
     page script offer nothing. A click elsewhere before the real send
     offers what was typed so far; the real send replaces it (one pending
     save per tab and frame), and nothing is stored until Save.
  4. **The password field must be usable.** It must be at least 16x8 CSS px
     and visible: not hidden by CSS, `display` or opacity
     (`checkVisibility`). A 1-pixel field that grabbed focus while the
     person typed elsewhere is ignored.

  Every input is tracked whatever its type, so typing while a
  show-password toggle has the field as `type=text` still counts when it is
  hidden again. Pending saves are kept per (tab, frame): a cross-origin
  iframe can neither replace the top frame's save nor be offered ahead of
  it.

  What this still does not catch:
  - **A visible decoy.** A page can move focus into a normal-sized password
    field while the person is typing elsewhere. Their own keystrokes then
    land there and count. If they then press Enter or click that form's
    submit control, those keystrokes are offered as a password.
  - **Which field the keys reach.** Nothing here stops a page from moving
    focus between fields while the person types, so a password can be split
    or merged across fields. Each character still is one the person typed.
  - **The audit's N8b case** (the page swaps the typed password after the
    person typed and before they submit) could be offered in the build
    audited at 875acea. It is no longer: the swap is an input that does not
    count, so nothing is offered.

  The person still has to click Save, and the card shows the site and the
  username.
- **Values:** never logged, never written to storage, never put in a badge,
  title, notification or error message, and never sent to the popup. A
  pending save lives only in worker memory, with a 3-minute TTL. A fill value
  lives in one local variable and is nulled after injection.
- **Worker lifetime:** both families stop an idle background after about
  30 s. That would drop an in-memory save before its TTL. So while a save,
  pairing or fill is in flight, the worker calls `runtime.getPlatformInfo()`
  every 20 s, which resets the idle timer in both. Chromium counts any
  extension API call. Firefox counts calls that reach the parent process
  (`"parentapicall"` in `ext-backgroundPage.js`), and this is one. It stops
  when nothing is pending. The Firefox smoke test checks both directions:
  the event page unloads when idle and comes back paired, and a pending
  save keeps it loaded for three idle timeouts.
- **Tokens:**
  - The access token is in `storage.session`: memory only, trusted contexts
    only. That is Chromium's default access level, and Firefox does not give
    content scripts `storage.session` at all.
  - The refresh token is in `storage.local`, sealed with AES-GCM under a
    non-extractable key kept in the extension's own IndexedDB. Content
    scripts can read **and write** `storage.local` by default, but they
    cannot open the extension origin's IndexedDB (`chrome-extension://<id>` /
    `moz-extension://<per-install UUID>`).
  - Nothing in `storage.local` is trusted as configuration. The API server
    setting lives in IndexedDB. Both tokens carry the API base they were
    issued by: the sealed blob holds `{ rt, base }`, and the session entry
    holds `{ t, base }`. A token is returned only under its own base. At
    startup, a session sealed for a different base is signed out locally
    and revoked at its own base. So is an older v1 blob, which records no
    base; it is signed out but not revoked anywhere, because its base is
    unknown. A `dp_api_base` key in `storage.local`, from older builds or
    written by anything else, is deleted unread.
  - Sign-out cannot be undone by a late answer. It bumps a generation
    counter before and after clearing the tokens. A refresh or pairing poll
    still in flight then revokes the pair it gets back instead of storing
    it, even when the sign-out lands between its check and its write.
    Sign-out waits up to 3 s for those, then finishes anyway. A server
    switch signs out the same way.
  - Refresh rotates the pair. It is single-flight, because the refresh token
    is single-use, and the new refresh token is persisted before the new
    access token is used.
  - A carbon fill request belongs to the one access token (`jti`) that made
    it; a refreshed token gets 404 on redeem. So before `/fill/request` the
    worker refreshes if the access token expires within 5 minutes. If a
    refresh happens anyway while the request waits, it asks once more and
    the popup shows "Approve on your phone…" again. A redeem 404 with the
    same token is final, for example "the login was deleted or revoked since
    the request". It is shown, and no second card is created. A 429 while
    polling backs off (doubling, up to 16 s) and keeps waiting.
  - Fill errors are shown as what they are. A 403 with `bound_origins`
    means "not bound to this site". "This token cannot hold a fill request"
    and worker tokens mean "sign out and pair again". Anything else shows
    the server's own short text.
  - A 401, or dustforge's 403 `admin access or Bearer token required` (what
    `getDemiPassActor` returns for a bad bearer when `ADMIN_API_KEY` is set),
    triggers one refresh and one retry. A 403 `denied` from redeem does not.
- **Origins:** `https` anywhere. Plain `http` only for `localhost` and
  `127.0.0.1`. Matching is exact.
- **The capture UI is the extension popup, not page DOM**, so the page cannot
  script it.
- **One API object.** `lib/browser.js` uses `browser.*` where it exists
  (Firefox, Zen; also recent Chromium) and `chrome.*` otherwise. Both return
  promises in MV3. No other file names either global, and a unit test
  checks that.
- No remote code and no runtime dependencies. The build step only copies
  files and writes the manifest. Extension pages run under
  `script-src 'self'; object-src 'none'`.

What it does not protect against is the same as in the contract. Whatever the
value is filled into can read it, and so can anything that drives the browser
(DevTools/CDP).

## Permissions

| Permission | Why |
|---|---|
| `storage` | Access token in `storage.session`; sealed refresh token in `storage.local`. (The dev-server setting is in the extension's IndexedDB.) |
| `contextMenus` | The **Store in DemiPass** item on selected text. Firefox accepts this name as well as `menus`. |
| `scripting` | The fill: `executeScript` into the exact document after approval. Also injects the detector into tabs opened before install. |
| `activeTab` | Grants `scripting` on the tab when the person clicks the toolbar button (or uses the context menu), so no broad host permission is needed for filling. |
| `host_permissions: https://api.dustforge.com/*` | The worker's API calls. In Firefox the person can revoke it; the popup then says DemiPass cannot connect and offers **Allow**. |
| `optional_host_permissions: <all_urls>` | Lets the popup ask for site access again with `permissions.request()`. **Allow on this site** asks for `scheme://host/*`; **Allow on all sites** asks for `<all_urls>`. Being optional, it adds no install-time prompt of its own. |
| content script on `<all_urls>`, all frames | Login-form detection and the submit capture. It reads password fields only at submit, and only to hand the value to the worker. **This is what produces the install-time warning** in Chromium ("Read and change all your data on all websites"), and Firefox lists it as access to all websites. Firefox runs it only where site access is granted. |

`webNavigation` is **not** requested. The browser-set `MessageSender` fields
plus `documentIds` targeting and the in-frame check give a tighter origin
guarantee than a separate `getFrame` lookup. A lookup would also have a gap
between the check and the injection, and the permission adds a "read your
browsing history" warning.

## Limits

- Filling a **cross-origin iframe** (an embedded login on another domain):
  - **Chromium** needs host permission for the frame's origin. The
    `<all_urls>` content-script match runs the detector there, and the frame
    is listed, but it does not let `scripting.executeScript` into the frame.
    Chromium 149 refuses with "Cannot access contents of the page. Extension
    manifest must request permission to access the respective host". That
    is the same for the top frame without `activeTab`. `activeTab` covers
    the tab's top-level origin, so such a fill stops before redeem and is
    withdrawn ("The page changed before the fill"). Granting the frame's
    site from **Allow on this site** in that site's own tab, or **Allow on
    all sites**, makes it work.
  - **Firefox** treats the content-script hosts as granted host
    permissions, so with site access on, iframe fills work.
- **Uninstalling does not sign out.** Removing the extension deletes its
  storage but does not revoke the refresh token on the server, and an
  uninstalled extension can run no code to do it. Sign out first, or revoke
  the session from another DemiPass session. `runtime.setUninstallURL` is
  not used: it could only open a web page, and that page has no token to
  revoke.
- **Logins not entered by the person's own keys, paste, drop or IME
  composition are not offered for saving.** That covers:
  - another password manager's fill;
  - the browser's own autofill;
  - DemiPass's own fill;
  - text committed with none of those events, which includes dictation and
    some on-screen or mobile keyboards that insert text directly.

  This is deliberate: to the content script they look the same as a page
  forging a value. Use **Add for this site** for them.
- The capture covers a click on a submit control or on any button that is
  not plainly something else, and Enter in any field. A login sent only by
  page script (for example after a timer) is not offered. Multi-step logins
  (username on one page, password on the next): the username the person
  typed and sent on step one is kept in memory for that tab for 5 minutes
  and names the save made on the same origin's password step. A username
  the page wrote itself is not used.
- Selection text is whatever the browser reports as `selectionText`, trimmed.
- The site-access check reads `permissions.getAll()` and matches the
  patterns itself. Chromium's `permissions.contains()` answers false for
  hosts granted through `content_scripts` matches, even though `getAll()`
  lists them.
- In Firefox's popup, `permissions.request()` opens a doorhanger. If the
  popup closes before the answer arrives, the grant still applies, and the
  next popup shows it.
- No icons yet. Each browser shows its default.

## Develop and test

See **Install** above. After a source change, run `npm run build:extension`
and reload the extension (Chromium: the reload icon on the extension card;
Firefox: **Reload** in `about:debugging`).

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
npm run test:extension        # node:test unit tests: origin, form detection, API state machine, refresh, mock
                              # round trip, cross-browser sender/target/permission logic, injected fill, build + packages
PLAYWRIGHT_CORE=/path/to/node_modules/playwright-core npm run test:extension:e2e     # Playwright Chromium
PLAYWRIGHT_CORE=… node extension/test/e2e/smoke.js --browser=chrome,brave            # Chrome for Testing, Brave
node extension/test/e2e/smoke.js --browser=firefox,zen                               # geckodriver
PLAYWRIGHT_CORE=… npm run test:extension:e2e:all                                     # all five
```

The smoke test builds the extension, loads it headless into each browser,
and runs the same steps against the mock server and a local login page.
Playwright drives the Chromium-family browsers. geckodriver drives the Gecko
browsers over plain WebDriver and installs the `.xpi` as a temporary add-on,
because Playwright's Firefox cannot load extensions. The test looks for
binaries in `~/.local/opt/`. Override with `CHROME_BIN`, `BRAVE_BIN`,
`FIREFOX_BIN`, `ZEN_BIN` and `GECKODRIVER`. A browser that is not installed
is skipped. Branded Google Chrome 137+ ignores `--load-extension`, so
"chrome" means Chrome for Testing, which is the same build.

Test-only changes to what is loaded:
- `http://localhost/*` and `http://127.0.0.1/*` host permissions. Headless
  browsers have no toolbar button to click for `activeTab`. In Firefox the
  test first revokes these grants, then gets them back through the popup's
  **Allow on this site** and **Allow on all sites** buttons.
- Gecko only: an empty `ui/blank.html`. The test runs its extension API
  calls there, because WebDriver has no handle on Firefox's event page.

Gecko-only steps:
- Site access is off, then granted from the popup. The test grants
  activeTab the way a toolbar click does.
- The event page unloads after its idle timeout (25 s for the run) and
  comes back paired.
- A pending save keeps the event page loaded for 75 s.

Every browser's run first checks with a canary that console capture works.
Then it asserts that no secret value reached any console.
