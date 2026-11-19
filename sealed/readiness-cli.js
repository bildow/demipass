#!/usr/bin/env node
"use strict";
// Environment-selected private files, identical to MCP. No installation or writes.
try {
  if (process.argv.length !== 2) throw Error("no command-line overrides");
  const report = require("./readiness").localReadiness();
  console.log(JSON.stringify(report, null, 2));
  process.exitCode = report.status === "hold" ? 2 : 0;
} catch (_) {
  console.error("readiness held: invalid invocation"); process.exitCode = 2;
}
