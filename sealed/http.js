"use strict";
const { timingSafeEqual } = require("node:crypto");
// Constant-time bearer comparison (#41 review L3): a length mismatch is a mismatch, compared on equal-length buffers.
function sameSecret(a, b) {
  const x = Buffer.from(String(a || ""), "utf8"), y = Buffer.from(String(b || ""), "utf8");
  return x.length === y.length && timingSafeEqual(x, y);
}
const http = require("node:http"),
  https = require("node:https");
function request(
  url,
  body,
  { token, timeout = 10000, fixture = false, method = "POST" } = {},
) {
  const u = new URL(url);
  if (
    u.protocol !== "https:" &&
    !(
      fixture &&
      u.protocol === "http:" &&
      ["127.0.0.1", "[::1]"].includes(u.hostname)
    )
  )
    throw Error("HTTPS required");
  if (u.username || u.password || u.hash) throw Error("invalid endpoint");
  const raw = body === undefined ? null : Buffer.from(JSON.stringify(body));
  if (raw && raw.length > 98304) throw Error("request too large");
  return new Promise((resolve, reject) => {
    const req = (u.protocol === "https:" ? https : http).request(
      u,
      {
        method,
        headers: {
          "content-type": "application/json",
          ...(token ? { authorization: "Bearer " + token } : {}),
          ...(raw ? { "content-length": raw.length } : {}),
        },
      },
      (res) => {
        let n = 0;
        const chunks = [];
        res.on("data", (b) => {
          n += b.length;
          if (n > 98304) {
            req.destroy(Error("response too large"));
            return;
          }
          chunks.push(b);
        });
        res.on("error", reject);
        res.on("end", () => {
          clearTimeout(timer);
          if (res.statusCode !== 200 && res.statusCode !== 201)
            return reject(
              Object.assign(Error("service refused request"), {
                status: res.statusCode,
              }),
            );
          try {
            resolve(JSON.parse(Buffer.concat(chunks)));
          } catch {
            reject(Error("invalid JSON response"));
          }
        });
      },
    );
    const timer = setTimeout(
      () => req.destroy(Error("request deadline")),
      timeout,
    );
    req.on("error", reject);
    req.on("close", () => clearTimeout(timer));
    req.end(raw);
  });
}
function serve(handler, { token, port = 0, fixture = false, tls, host = "127.0.0.1", authorization, policy } = {}) {
  if (!fixture) {
    require("./runtime-authorization").assertAuthorization(authorization, policy);
    if (!tls || typeof tls.key !== "string" || typeof tls.cert !== "string") throw Error("TLS required");
  } else if (tls || host !== "127.0.0.1") throw Error("fixture must stay loopback");
  if (typeof token !== "string" || token.length < 32)
    throw Error("private service credential required");
  let active = 0;
  const handle = (req, res) => {
    const answer = (status, obj) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(obj));
    };
    if (req.method !== "POST" || req.url !== "/release")
      return answer(404, { error: "not_found" });
    if (!sameSecret(req.headers.authorization, "Bearer " + token))
      return answer(403, { error: "unauthorized" });
    if (active >= 32) return answer(429, { error: "busy" });
    active++;
    let released = false,
      processing = false;
    const releaseSlot = () => {
      if (!released) {
        released = true;
        active--;
      }
    };
    res.once("close", () => {
      if (!processing) releaseSlot();
    });
    const chunks = [];
    let n = 0,
      oversize = false;
    req.on("data", (b) => {
      n += b.length;
      if (n > 98304) {
        if (!oversize) {
          oversize = true;
          answer(413, { error: "too_large" });
        }
        return;
      }
      chunks.push(b);
    });
    req.on("end", async () => {
      if (oversize) return;
      let body;
      try {
        body = JSON.parse(Buffer.concat(chunks));
      } catch {
        return answer(400, { error: "invalid_json" });
      }
      processing = true;
      try {
        const r = await handler(body, req);
        answer(200, r);
      } catch {
        answer(409, {
          error: "release_held",
          detail: "Check local non-secret audit status; no plaintext fallback.",
        });
      } finally {
        releaseSlot();
      }
    });
  };
  const server = fixture ? http.createServer(handle) : https.createServer({key:tls.key, cert:tls.cert, minVersion:"TLSv1.3"}, handle);
  server.requestTimeout = 15000;
  server.headersTimeout = 10000;
  server.setTimeout(20000, (s) => s.destroy());
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () =>
      resolve({
        server,
        url: (fixture ? "http://" : "https://") + (host.includes(":") ? "["+host+"]" : host) + ":" + server.address().port,
        close: async () => {
          server.closeAllConnections();
          await new Promise((r) => server.close(r));
        },
      }),
    );
  });
}
module.exports = { request, serve };
