# Conduit Wave 5 — billing and recovery

Status: source work; not live acceptance. Base is Wave 4 SDK merge
25d3e6104e0e495ba1323c071ced3822f9285cb8. Guardian release and its surcharge
remain OFF. The 2 DD ceiling covers one guarded key-release package, not relay
post/read/ack fees, reviewer spending, or a promise of successful decryption.

## Dependency map and acceptance

Flight A: gateway maximum-total contract and signed lookup (A1) -> SDK consumer
(A2). Flight B: concurrent retry/restart evidence (B1) and durable signed dispute
intake (B2) depend on A2. Flight C: exact-head independent reviews of BOTH repos
(C1) -> approved real DemiPass test (C2). Wave 6 independent custody/deployment
follows. Fixture success cannot close C2 or authorize live keys/charges.

## Payment contract

`GET /api/services/conduit-keys` must advertise `charge_contract` version 1,
`max_total_dd: true`, `signed_lookup: true`, exact action `release` at measured
and maximum cost 2 and zero margin. Older gateways hold before any charge.
Every charge and dry run carries `max_total_dd: 2`. The gateway validates a
positive safe integer; compares the total including margin; re-reads current
active tenant/action/margin under the existing IMMEDIATE transaction before any
debit; refuses changed configuration. Debit, credit and idempotency row remain
one transaction. The ceiling is per immutable charge, not a new budget grant.
A dry run reserves nothing. Token and daily caps remain independent constraints.

The tenant's exact-key lookup now includes original receipt/signature. The SDK
checks pinned issuer, service, key, action, cost, zero margin and total from signed
bytes. It disregards unsigned projection fields for recovery. Coordinator checks
payer; another wallet cannot recover the package. A fresh charge also attests the
ceiling. On explicit replay a renewed token may receive the original token's
receipt for the same payer. This does not mint new authority.

Encrypted fulfillment is fsynced before debit; paid state is fsynced before
return. Unknown lookup/payment or persistence failure holds. Retry uses the same
key and original package; no new request ID can produce another fee for the same
envelope/recipient/policy. Missing local fulfillment despite a known debit holds;
it is not reconstructed. One locked service owner per journal is required across
processes (`service.sh`); the coordinator's key queue serializes local requests.
The server transaction/unique key also protects concurrent HTTP duplicate debits.

## Failure and dispute policy

A signature authenticates a guardian, not the correctness of its encrypted share.
The 2 DD pays for the durable release package. No model or service should promise
that it proves decryption. Recipient failure must be surfaced as failure.

`Coordinator.dispute(request, token, complaint)` accepts an exact typed
recipient-signed body: version 1, type `conduit-release-dispute`, envelope_hash,
grant_hash and reason (decryption_failed/package_unavailable/billing_mismatch).
It authenticates the wallet and original paid grant, persists before responding,
and returns `manual_review_required`, `refund: not_issued`. Duplicate identical
complaints replay the same record. No plaintext, raw key or extra share is added.
The fixture coordinator accepts this via `/release` with `operation: dispute`;
unknown operations refuse. This is local intake, not external notification.

No automatic refund exists. Payment uncertainty must reconcile before a complaint
can be tied to a paid record. A missing/corrupt local journal needs operator-led
restore from original backup or manual payment investigation. Never erase the
payment row, invent a negative charge, or change its idempotency key to retry.
Before live acceptance, an authorized operator must own dispute handling and a
separately audited credit/refund path with independent idempotency and original
charge binding must be chosen if refunds are offered. This wave does not grant
that authority. Local complaint persistence does not establish case delivery,
human resolution, or monetary credit.

## Evidence and live block

Local source tests exercise real SDK/HTTP paths with fixture identities and DD,
and the real gateway server with a disposable SQLite DB. They are not live DD.
A public read on 2026-11-17 found `/api/services/conduit-keys` HTTP 404 and the
ordinary Conduit tenant did not advertise the new charge contract. Do not route
release charges through `conduit/post`, Fleetgate, an operator wallet, or another
consent. The real payment gate is UNVERIFIED until the reviewed gateway contract
is deployed and a separately approved test tenant/consent/budget exists. No live
tenant or key has been provisioned by this work.
