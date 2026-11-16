"use strict";
// No real wallet, real DD, or network outside loopback. Mimics the published services API.
const http = require("node:http"),
  c = require("node:crypto");
function b58(b) {
  const chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let n = BigInt("0x" + b.toString("hex")),
    s = "";
  while (n) {
    s = chars[Number(n % 58n)] + s;
    n /= 58n;
  }
  return s;
}
async function meterFixture() {
  const keys = c.generateKeyPairSync("ed25519"),
    issuer =
      "did:key:z" +
      b58(
        Buffer.concat([
          Buffer.from([0xed, 1]),
          keys.publicKey.export({ format: "der", type: "spki" }).subarray(-32),
        ]),
      );
  const state = {
    margin: 0,
    service: "conduit-keys",
    action: "release",
    badLookup: false,
    badReceipt: false,
    charges: 0,
    verifyOk: true,
    ledger: new Map(),
  };
  const signed = (charge) => {
    const receipt = JSON.stringify({
        v: 1,
        type: "dustforge_service_charge",
        issuer,
        ...charge,
        ...(state.wrongToken ? { token_id: "another-token" } : {}),
      }),
      sig = c
        .sign(
          null,
          Buffer.from("dustforge-service-charge:v1\n" + receipt),
          keys.privateKey,
        )
        .toString("base64url");
    return {
      receipt,
      sig: state.badReceipt ? sig.slice(0, -5) + "AAAAA" : sig,
    };
  };
  const server = http.createServer((req, res) => {
    let raw = "";
    req.on("data", (b) => (raw += b));
    req.on("end", () => {
      const send = (code, v) => {
        res.writeHead(code, { "content-type": "application/json" });
        res.end(JSON.stringify(v));
      };
      if (req.headers.authorization !== "Bearer fixture-tenant-token")
        return send(403, {});
      const b = raw ? JSON.parse(raw) : {},
        url = new URL(req.url, "http://localhost");
      if (url.pathname === "/api/services/conduit-keys")
        return send(200, {
          slug: state.service,
          margin_pct: state.margin,
          actions: [
            { action: state.action, measured_cost_dd: 2, max_cost_dd: 2 },
          ],
        });
      if (url.pathname === "/api/services/verify")
        return b.token === "fixture-payer-token"
          ? send(200, {
              ok: state.verifyOk,
              wallet: "fixture-wallet",
              token_id: "fixture-token-id",
              action: "release",
            })
          : send(403, {});
      if (url.pathname === "/api/services/charges")
        return send(
          200,
          state.badLookup
            ? {}
            : {
                received: [
                  state.ledger.get(url.searchParams.get("idempotency_key")),
                ].filter(Boolean),
              },
        );
      if (url.pathname === "/api/services/charge") {
        if (
          b.action !== "release" ||
          b.cost_dd !== 2 ||
          b.token_id !== "fixture-token-id"
        )
          return send(400, {});
        if (b.dry_run) return send(200, { ok: true, would_charge_dd: 2 });
        let row = state.ledger.get(b.idempotency_key);
        if (!row) {
          state.charges++;
          row = {
            charge_id: "fixture-charge-" + state.charges,
            service: "conduit-keys",
            payer: "fixture-wallet",
            payee: "fixture-service",
            action: "release",
            cost_dd: 2,
            margin_pct: 0,
            dd: 2,
            token_id: b.token_id,
            idempotency_key: b.idempotency_key,
            at: new Date().toISOString(),
          };
          state.ledger.set(b.idempotency_key, row);
        }
        return send(201, { ok: true, ...row, ...signed(row) });
      }
      send(404, {});
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return {
    state,
    config: {
      url: "http://127.0.0.1:" + server.address().port,
      token: "fixture-tenant-token",
      issuer,
      fixture: true,
    },
    close: async () => {
      server.closeAllConnections();
      await new Promise((r) => server.close(r));
    },
  };
}
module.exports = { meterFixture };
