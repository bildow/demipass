# DemiPass for services: verify, charge, delegate, revoke

Your service is a **tenant**. It has its own DemiPass wallet, and callers reach it with DemiPass **service tokens**
locked to their wallet and to your service. For each call you:

1. verify the caller's token;
2. charge for the call: the caller's wallet is debited and yours is credited, in one transaction;
3. do the work.

You never see the person behind a wallet. People let their agents use your service by **delegating** a scope, and
**revoke** it the same way.

Server reference: dustforge `docs/service-tenants.md`. Module: `services.js` (`require('demipass').services`).

```js
const { services, verifyServiceReceipt } = require('demipass');
const dp = services({ token: process.env.DEMIPASS_TENANT_TOKEN });   // your tenant wallet's own token
```

Every non-2xx answer throws a `ServiceError` with `{status, body}`. **Pass both on to your caller unchanged:**

| status | meaning |
|---|---|
| 402 | the caller can't pay: no consent (`consent_required`), too little DD (`top_up`), the token's cap or the daily cap reached |
| 401 | bad, expired, revoked or wrong-audience token |
| 403 | the wallet has no authority for the action |
| 202 | from verify, `err.pending === true`: an elevated action waits on a person's phone; `body.approval_id` |

## 0. Once: register, and publish your prices

```js
// The service wallet registers itself (a fleet silicon's tenant belongs to its fleet owner).
await dp.register({ slug: 'conduit', name: 'Conduit' });
await dp.setActions('conduit', [
  { action: 'post',      scope: 'post',      measured_cost_dd: 2 },                        // open: any wallet, own account
  { action: 'broadcast', scope: 'broadcast', measured_cost_dd: 20, depth: 'elevated' },    // each call approved on a phone
  { action: 'admin',     scope: 'admin',     measured_cost_dd: 1, open: false },           // your owner and their delegates
]);
```

Prices are your measured cost per call, in DD (1 DD = $0.001). DemiPass adds the platform margin, and
`GET /api/services/conduit` publishes cost, margin and price. When cost varies per call, set `max_cost_dd` and
charge each call's actual cost up to it.

## 1. verify

```js
const who = await dp.verify({ token: bearerFrom(req), action: 'post' });
// → { wallet: 'did:key:z6Mk…', token_id: '3f9c…', scope: 'transact', depth: 'standard', via: 'own' | 'delegation',
//     principal: 'pp_…' (delegated calls only: stable per person, here only), price: {…}, cap_dd: 500, spent_dd: 24 }
```

For an elevated action, pass `call`: the exact parameters the person approves, which are shown on their phone.

```js
try {
  await dp.verify({ token, action: 'broadcast', call: { room: 'ops', text_sha256: h } });
} catch (e) {
  if (e.pending) return res.status(202).json(e.body);   // the caller retries with approval_id when it's approved
  throw e;
}
// retry: same call + approval_id; passes once (another call → 409, a second use → 410)
await dp.verify({ token, action: 'broadcast', call: { room: 'ops', text_sha256: h }, approvalId: req.body.approval_id });
```

## 2. charge

```js
const c = await dp.charge({ action: 'post', costDd: 2, tokenId: who.token_id, idempotencyKey: `msg:${messageId}` });
// 201 → { charge_id: 'sc_…', cost_dd: 2, margin_pct: 20, dd: 3, token_id, receipt, sig, issuer }
// the same idempotencyKey again → 200 { replayed: true, … }: a retried request is never billed twice
```

You can only charge a token you verified, and only while it lives. Charge before doing fixed-price work, so a caller
who can't pay gets the 402 first. `metered()` does verify → charge → work in that order:

```js
app.post('/messages', async (req, res) => {
  try {
    const { result, charge } = await dp.metered(
      { token: bearerFrom(req), action: 'post', costDd: 2, idempotencyKey: `msg:${req.body.client_msg_id}` },
      async (who) => store.post({ from: who.wallet, thread: req.body.thread_id, text: req.body.text }));
    res.status(201).json({ ...result, charge_id: charge.charge_id });
  } catch (e) {
    if (e.name === 'ServiceError') return res.status(e.status || 502).json(e.body);
    throw e;
  }
});
```

Receipts verify offline (Ed25519 over `"dustforge-service-charge:v1\n"` + the receipt string). Pin the issuer from `GET https://api.dustforge.com/api/meter/key`:

```js
verifyServiceReceipt({ receipt: c.receipt, sig: c.sig }, { issuer: PINNED_ISSUER });   // { valid: true, charge: {…} }
```

## Before any of it, the caller consents to pay you (caller side)

A charge moves DD out of the caller's wallet, so a wallet pays a service only under a standing consent with a daily
cap. The person who answers for the wallet approves it in the DemiPass app: the person themselves, or an agent's
fleet owner. A token alone can ask, never grant.

```js
try { await me.consent({ service: 'conduit', dailyCapDd: 500 }); }
catch (e) { if (!e.pending) throw e; /* approved in the app → */ await me.consent({ service: 'conduit', dailyCapDd: 500, approvalId: e.body.approval_id }); }
```

## 3. delegate (caller side)

A person lets an agent their own fleet created use a scope at your service. It is use-only: the agent can't hand it on. The agent
calls you with its own service token and pays from its own wallet. You see `via: 'delegation'` and a pairwise
`principal` for the person.

```js
const me = services({ token: personSessionToken });   // the person's own session, never an agent token
await me.delegate({ service: 'conduit', scope: 'post', delegateDid: agentDid });   // another fleet's agent → 403
```

The agent mints a token for your service and sends it:

```js
const agent = services({ token: agentToken });
const { token } = await agent.mintToken({ service: 'conduit', ttl: '1h', capDd: 200 });
await fetch('https://conduit…/messages', { method: 'POST', headers: { authorization: `Bearer ${token}` }, body });
```

A service token opens nothing at DemiPass itself, so you can't misuse one you receive. Its `cap_dd` is the most it
can ever be charged.

## 4. revoke

```js
await me.revokeDelegation({ delegationId });   // the person ends the delegation: the agent's next verify → 403
await agent.revokeToken({ tokenId });          // a caller kills one service token: verify and charge → 401
```

## What you never get

- The person's name, email or wallet. You get the calling wallet's DID, plus a pairwise id when an agent acts for a person.
- A way to charge more than the action's `max_cost_dd` plus the margin per call, or more than the token's `cap_dd` in total.
- A way to weaken your own gates (a lower depth, an opened action, a widened scope) without your owner's approval.
- A charge on a wallet that hasn't consented to you, or for an action you didn't verify on that token.
