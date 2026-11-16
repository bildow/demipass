"use strict";
// The runner is a local integration fixture, not a production enrollment escape hatch.
const path = require("node:path"),
  fs = require("node:fs");
const { readPrivate, privateDirectory } = require("./client"),
  { Journal } = require("./journal");
const { Guardian, Coordinator } = require("./guardian"),
  { DemiPassMeter } = require("./demipass-meter"),
  { request, serve } = require("./http");
function loopback(url) {
  const u = new URL(url);
  if (
    u.protocol !== "http:" ||
    u.hostname !== "127.0.0.1" ||
    u.username ||
    u.password
  )
    throw Error("fixture endpoints must be loopback");
  return url;
}
async function main() {
  const dir = path.resolve(process.argv[2] || "");
  privateDirectory(dir);
  const cfg = readPrivate(path.join(dir, "config.json"));
  if (cfg.fixture !== true) throw Error("live guardian release disabled");
  if (!["guardian", "coordinator"].includes(cfg.role))
    throw Error("unknown role");
  if (
    cfg.port !== undefined &&
    (!Number.isInteger(cfg.port) || cfg.port < 0 || cfg.port > 65535)
  )
    throw Error("invalid port");
  // Require inherited lock descriptor from the shell runner. A root/same-user attacker
  // could bypass this check, just as it could read every local key: not independent custody.
  const a = fs.fstatSync(9),
    b = fs.lstatSync(path.join(dir, "lease.lock"));
  if (!a.isFile() || a.ino !== b.ino || a.dev !== b.dev || b.isSymbolicLink())
    throw Error("run through service.sh");
  const journal = new Journal(path.join(dir, "journal.jsonl"));
  let service;
  if (cfg.role === "guardian") service = new Guardian({ ...cfg, journal });
  else {
    loopback(cfg.meter.url);
    const guardians = Object.fromEntries(
      Object.entries(cfg.guardian_endpoints || {}).map(([id, g]) => {
        loopback(g.url);
        return [
          id,
          (r) =>
            request(
              g.url + "/release",
              {
                envelope: r.envelope,
                capsule: r.capsule,
                grant: r.grant,
                approval: r.approvals && r.approvals[id],
              },
              { token: g.token, fixture: true },
            ),
        ];
      }),
    );
    service = new Coordinator({
      ...cfg,
      journal,
      guardians,
      meter: new DemiPassMeter({ ...cfg.meter, fixture: true }),
    });
  }
  const server = await serve(
    (body) =>
      cfg.role === "guardian"
        ? service.release(body)
        : service.release(body.request, body.payer_token),
    { token: cfg.transport_token, port: cfg.port || 0, fixture: true },
  );
  console.log(
    JSON.stringify({
      fixture: true,
      role: cfg.role,
      url: server.url,
      live_release_enabled: false,
    }),
  );
  for (const sig of ["SIGINT", "SIGTERM"])
    process.once(sig, () => {
      server.server.closeAllConnections();
      server.server.close();
      journal.close();
      process.exit(0);
    });
}
main().catch(() => {
  console.error(
    "sealed service held: invalid fixture configuration, lock, or journal; no live fallback",
  );
  process.exitCode = 1;
});
