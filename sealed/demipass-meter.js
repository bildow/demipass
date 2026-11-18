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
      info.charge_contract?.version !== 1 ||
      info.charge_contract.max_total_dd !== true ||
      info.charge_contract.signed_lookup !== true ||
      info.slug !== this.service ||
      info.margin_pct !== 0 ||
      !action ||
      action.measured_cost_dd !== 2 ||
      action.max_cost_dd !== 2
    )
      throw Error("release must be published at exactly 2 DD with zero margin and atomic charge contract");
    return this.identifyDispute(token, binding);
  }
  // Existing paid complaints require current authenticated identity, not today's
  // price/charge contract or eligibility to buy a second release. Verification
  // still enforces the tenant, active token/wallet and release-action authority.
  async identifyDispute(token, binding) {
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
    if (cost !== 2) throw Error("release cost must be 2 DD");
    const r = await this.call("/api/services/charge", {
      action: "release",
      cost_dd: cost,
      max_total_dd: 2,
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
    // Recovery uses original issuer-signed bytes, never a mutable list projection.
    return this.receipt(r.received[0], key);
  }
  async charge(who, cost, key) {
    if (cost !== 2) throw Error("release cost must be 2 DD");
    const r = await this.call("/api/services/charge", {
      action: "release",
      cost_dd: cost,
      max_total_dd: 2,
      token_id: who.token_id,
      idempotency_key: key,
    });
    const result = this.receipt(r, key);
    // Fresh debits must attest the ceiling. Same-wallet token renewal may replay
    // an older token's receipt; recovery binds the payer, not today's token ID.
    if (result.wallet !== who.wallet || result.max_total_dd !== 2 ||
        (result.token_id !== who.token_id && r.replayed !== true))
      throw Error("payment receipt payer/ceiling mismatch");
    return result;
  }
  receipt(r, key) {
    const v = verifyReceipt(r, { issuer: this.issuer });
    if (
      !v.valid ||
      v.charge.service !== this.service ||
      v.charge.idempotency_key !== key ||
      typeof v.charge.payer !== "string" || !v.charge.payer ||
      typeof v.charge.token_id !== "string" || !v.charge.token_id ||
      typeof v.charge.charge_id !== "string" || !v.charge.charge_id ||
      v.charge.margin_pct !== 0 ||
      v.charge.action !== "release" ||
      v.charge.dd !== 2 ||
      v.charge.max_total_dd !== 2 ||
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
