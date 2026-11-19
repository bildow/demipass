'use strict';
// Network membership must never be an MCP/API onboarding prerequisite.
// Loopback remains available for local stdio bridges and isolated tests.
const dns = require('dns');
const net = require('net');

function hostOf(value) { return String(value).toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, ''); }
function loopback(host) {
  host = hostOf(host);
  return host === 'localhost' || host === '::1' || /^127\./.test(host) && net.isIP(host) === 4;
}
function privateAddress(host) {
  host = hostOf(host);
  if (host.startsWith('::ffff:')) {
    const rest = host.slice(7);
    if (net.isIP(rest) === 4) return privateAddress(rest);
    const m = /^([a-f0-9]{1,4}):([a-f0-9]{1,4})$/.exec(rest);
    if (m) { const a = parseInt(m[1],16), b = parseInt(m[2],16); return privateAddress(`${a>>8}.${a&255}.${b>>8}.${b&255}`); }
  }
  if (net.isIP(host) === 4) {
    const [a,b] = host.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 || a === 169 && b === 254 ||
      a === 172 && b >= 16 && b <= 31 || a === 192 && b === 168 ||
      a === 100 && b >= 64 && b <= 127 || a >= 224;
  }
  return net.isIP(host) === 6 && (host === '::' || host === '::1' || /^(fc|fd|fe[89ab]|ff)/i.test(host));
}
function failure() { return Object.assign(new Error('Public HTTPS service endpoint required; private/tailnet routes are not permitted for MCP, API calls or onboarding'), { code: 'PRIVATE_SERVICE_ROUTE' }); }
function assertPublicRoute(value) {
  const u = value instanceof URL ? value : new URL(value);
  const host = hostOf(u.hostname);
  if (u.username || u.password || !['http:', 'https:'].includes(u.protocol)) throw failure();
  if (loopback(host)) return u;
  if (u.protocol !== 'https:' || host === 'ts.net' || host.endsWith('.ts.net') ||
      host === 'tailscale.com' || host.endsWith('.tailscale.com') ||
      !host.includes('.') && !net.isIP(host) || privateAddress(host)) throw failure();
  return u;
}
// Check the exact DNS answer used by the connection, not a separate preflight
// lookup that could race a second resolution. An unexpected private answer holds.
function publicLookup(hostname, options, callback) {
  if (typeof options === 'function') { callback = options; options = {}; }
  dns.lookup(hostname, options, (err, address, family) => {
    if (err) return callback(err);
    const addresses = Array.isArray(address) ? address : [{ address, family }];
    if (addresses.some(a => loopback(hostname) ? !loopback(a.address) : privateAddress(a.address))) return callback(failure());
    callback(null, address, family);
  });
}
module.exports = { assertPublicRoute, publicLookup, privateAddress };
