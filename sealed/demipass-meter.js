"use strict";
const { request } = require("./http");
const { verifyReceipt } = require("../services");
// Separate tenant, explicit release action. Never fall back to post, provision keys, or increase a cap.
class DemiPassMeter {
  constructor({
    url,
    token,
    issuer,
    service = "conduit-keys",
    fixture = false,
  }) {
    if (!url || !token || !issuer || service !== "conduit-keys")
      throw Error("pinned key-service meter configuration required");
    this.url = url.replace(/\/$/, "");
    this.token = token;
    this.issuer = issuer;
    this.service = service;
    this.fixture = fixture;
  }
  call(path, body, method = "POST") {
    return request(this.url + path, body, {
      token: this.token,
      method,
      fixture: this.fixture,
    });
  }
  async identify(token, binding) {
    const info = await this.call(
      "/api/services/" + this.service,
      undefined,
      "GET",
    );
    const action = (info.actions || []).find(
      (x) => x.action === "release" && !x.retired,
    );
    if (
      info.slug !== this.service ||
      info.margin_pct !== 0 ||
      !action ||
      action.measured_cost_dd !== 2 ||
      action.max_cost_dd !== 2
    )
      throw Error("release must be published at exactly 2 DD with zero margin");
    const who = await this.call("/api/services/verify", {
      token,
      action: "release",
      call: binding,
    });
    if (
      who.ok !== true ||
      who.action !== "release" ||
      typeof who.wallet !== "string" ||
      typeof who.token_id !== "string"
    )
      throw Error("release verification mismatch");
    return who;
  }
  async precheck(who, cost) {
    const r = await this.call("/api/services/charge", {
      action: "release",
      cost_dd: cost,
      token_id: who.token_id,
      dry_run: true,
    });
    if (r.ok !== true || r.would_charge_dd !== 2)
      throw Error("exact charge unavailable");
  }
  async lookup(key) {
    const r = await this.call(
      "/api/services/charges?idempotency_key=" + encodeURIComponent(key),
      undefined,
      "GET",
    );
    if (!Array.isArray(r.received) || r.received.length > 1)
      throw Error("unreadable charge lookup");
    if (!r.received.length) return null;
    const row = r.received[0];
    if (row.service !== this.service) throw Error("wrong service charge");
    return { ...row, wallet: row.payer };
  }
  async charge(who, cost, key) {
    const r = await this.call("/api/services/charge", {
      action: "release",
      cost_dd: cost,
      token_id: who.token_id,
      idempotency_key: key,
    });
    const v = verifyReceipt(r, { issuer: this.issuer });
    if (
      !v.valid ||
      v.charge.service !== this.service ||
      v.charge.idempotency_key !== key ||
      v.charge.payer !== who.wallet ||
      v.charge.action !== "release" ||
      v.charge.dd !== 2 ||
      v.charge.cost_dd !== 2
    )
      throw Error("payment receipt mismatch");
    return {
      ...v.charge,
      wallet: v.charge.payer,
      receipt: r.receipt,
      sig: r.sig,
    };
  }
}
module.exports = { DemiPassMeter };
