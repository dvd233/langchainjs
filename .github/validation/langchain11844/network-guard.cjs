/* Every test/build Node process loads this through inherited NODE_OPTIONS. */
const fs = require('node:fs');
const auditPath = process.env.NETWORK_AUDIT_LOG;
function audit(event, detail) {
  if (auditPath) fs.appendFileSync(auditPath, JSON.stringify({ event, pid: process.pid, detail }) + '\n');
}
audit('guard-loaded', process.argv[1] || 'worker');
let attempts = 0;
const deny = (kind) => function () {
  attempts++;
  audit('network-blocked', kind);
  const error = new Error(`NETWORK_DISABLED_BY_VALIDATION: ${kind}`);
  error.code = 'NETWORK_DISABLED_BY_VALIDATION';
  throw error;
};
globalThis.fetch = deny('fetch');
globalThis.WebSocket = class { constructor() { deny('WebSocket')(); } };
for (const name of ['http', 'https']) {
  const mod = require(`node:${name}`);
  mod.request = deny(`${name}.request`);
  mod.get = deny(`${name}.get`);
}
const net = require('node:net');
net.connect = deny('net.connect');
net.createConnection = deny('net.createConnection');
net.Socket.prototype.connect = deny('net.Socket.connect');
require('node:tls').connect = deny('tls.connect');
require('node:http2').connect = deny('http2.connect');
const dns = require('node:dns');
for (const key of Object.keys(dns)) {
  if (key === 'lookup' || key === 'lookupService' || key.startsWith('resolve')) {
    if (typeof dns[key] === 'function') dns[key] = deny(`dns.${key}`);
    if (typeof dns.promises[key] === 'function') dns.promises[key] = deny(`dns.promises.${key}`);
  }
}
// Vite compares localhost lookup ordering at startup. Resolve it entirely in
// process; never call the original DNS implementation or permit a connection.
function localhostResult(options) {
  const family = options === 6 || options?.family === 6 ? 6 : 4;
  const result = { address: family === 6 ? '::1' : '127.0.0.1', family };
  return options?.all ? [result] : result;
}
dns.promises.lookup = async (hostname, options) => {
  if (hostname !== 'localhost') return deny('dns.promises.lookup')();
  audit('localhost-resolved-offline', 'dns.promises.lookup');
  return localhostResult(options);
};
dns.lookup = (hostname, options, callback) => {
  if (hostname !== 'localhost') return deny('dns.lookup')();
  if (typeof options === 'function') { callback = options; options = {}; }
  audit('localhost-resolved-offline', 'dns.lookup');
  const result = localhostResult(options);
  queueMicrotask(() => options?.all ? callback(null, result) : callback(null, result.address, result.family));
};
const dgram = require('node:dgram');
dgram.Socket.prototype.connect = deny('dgram.Socket.connect');
dgram.Socket.prototype.send = deny('dgram.Socket.send');
require('node:module').syncBuiltinESMExports();
globalThis.validationNetworkAttempts = () => attempts;
