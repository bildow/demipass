"use strict";
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
function serve(handler, { token, port = 0, fixture = false } = {}) {
  if (!fixture) throw Error("live guardian release disabled");
  if (typeof token !== "string" || token.length < 32)
    throw Error("private service credential required");
  let active = 0;
  const server = http.createServer((req, res) => {
    const answer = (status, obj) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(obj));
    };
    if (req.method !== "POST" || req.url !== "/release")
      return answer(404, { error: "not_found" });
    if (req.headers.authorization !== "Bearer " + token)
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
  });
  server.requestTimeout = 15000;
  server.headersTimeout = 10000;
  server.setTimeout(20000, (s) => s.destroy());
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () =>
      resolve({
        server,
        url: "http://127.0.0.1:" + server.address().port,
        close: async () => {
          server.closeAllConnections();
          await new Promise((r) => server.close(r));
        },
      }),
    );
  });
}
module.exports = { request, serve };
