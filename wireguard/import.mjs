// Offline importer for the pinned wg-easy 15.4.0 database schema.
import { createPrivateKey, createPublicKey } from 'node:crypto';
import { readFileSync, readdirSync, existsSync, chmodSync } from 'node:fs';
import { join, basename, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';
import { DatabaseSync } from 'node:sqlite';

function check(condition, message) { if (!condition) throw new Error(message); }
export function keyBytes(key) {
  check(/^[A-Za-z0-9+/]{43}=$/.test(key), 'Invalid WireGuard key encoding');
  const bytes = Buffer.from(key, 'base64');
  check(bytes.length === 32 && bytes.toString('base64') === key, 'Invalid WireGuard key length');
  return bytes;
}
export function publicKey(key) {
  const der = Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), keyBytes(key)]);
  return createPublicKey(createPrivateKey({ key: der, format: 'der', type: 'pkcs8' }))
    .export({ format: 'der', type: 'spki' }).subarray(-32).toString('base64');
}
function ipv4(value) {
  const parts = value.split('.');
  check(parts.length === 4 && parts.every(p => /^(0|[1-9]\d{0,2})$/.test(p) && Number(p) <= 255), 'Invalid IPv4 address');
  return parts.reduce((acc, p) => acc * 256 + Number(p), 0);
}
const formatIp = n => [24, 16, 8, 0].map(s => (n >>> s) & 255).join('.');

export function parseConfig(text, serverAddress) {
  const [address, prefixText, extra] = serverAddress.split('/');
  const prefix = Number(prefixText);
  check(!extra && /^\d+$/.test(prefixText ?? '') && prefix >= 1 && prefix <= 30, 'Expected IPv4 server address/prefix');
  const addressInt = ipv4(address), size = 2 ** (32 - prefix);
  const network = Math.floor(addressInt / size) * size;
  check(addressInt === network + 1, 'wg-easy requires the first usable subnet address for the server');
  const sections = [];
  let current;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.split('#', 1)[0].trim();
    if (!line) continue;
    if (/^\[(Interface|Peer)\]$/.test(line)) {
      current = { type: line.slice(1, -1), fields: {} }; sections.push(current); continue;
    }
    const match = /^([A-Za-z]+)\s*=\s*(.*?)\s*$/.exec(line);
    check(current && match, 'Invalid configuration line');
    const [, name, value] = match;
    const supported = current.type === 'Interface' ? ['PrivateKey', 'ListenPort'] : ['PublicKey', 'PresharedKey', 'AllowedIPs', 'Endpoint'];
    check(supported.includes(name), `Unsupported field ${name}; refusing a lossy migration`);
    check(!(name in current.fields), `Duplicate field ${name}`);
    current.fields[name] = value;
  }
  check(sections[0]?.type === 'Interface' && sections.filter(s => s.type === 'Interface').length === 1, 'Expected exactly one leading Interface section');
  const server = sections[0].fields, serverPublicKey = publicKey(server.PrivateKey ?? '');
  check(/^\d+$/.test(server.ListenPort ?? '') && Number(server.ListenPort) > 0 && Number(server.ListenPort) <= 65535, 'Invalid ListenPort');
  const addresses = new Set(), keys = new Set();
  const peers = sections.slice(1).map(({ fields }) => {
    keyBytes(fields.PublicKey ?? '');
    if (fields.PresharedKey) keyBytes(fields.PresharedKey);
    const match = /^([0-9.]+)\/32$/.exec(fields.AllowedIPs ?? '');
    check(match, 'Each peer must have exactly one IPv4 /32 AllowedIPs');
    const ip = ipv4(match[1]);
    check(ip > network + 1 && ip < network + size - 1, 'Peer address is outside the usable client range');
    check(!addresses.has(ip) && !keys.has(fields.PublicKey) && fields.PublicKey !== serverPublicKey, 'Duplicate peer address/key or peer uses server key');
    addresses.add(ip); keys.add(fields.PublicKey);
    if (fields.Endpoint) {
      const endpoint = /^([a-zA-Z0-9.-]+|\[[a-fA-F0-9:]+\]):([0-9]+)$/.exec(fields.Endpoint);
      check(endpoint && Number(endpoint[2]) > 0 && Number(endpoint[2]) <= 65535, 'Invalid peer endpoint');
    }
    // wg-easy always emits PresharedKey. WireGuard's all-zero key means no PSK;
    // an empty value would generate an invalid wg-quick configuration.
    return { publicKey: fields.PublicKey, preSharedKey: fields.PresharedKey || Buffer.alloc(32).toString('base64'), address: match[1], endpoint: fields.Endpoint ?? null };
  });
  check(peers.length > 0, 'No peers to import');
  return { privateKey: server.PrivateKey, publicKey: serverPublicKey, port: Number(server.ListenPort), cidr: `${formatIp(network)}/${prefix}`, peers };
}

export function importDatabase(options) {
  const config = parseConfig(readFileSync(options.config, 'utf8'), options.address);
  check(/^[a-zA-Z0-9][a-zA-Z0-9.-]*$/.test(options.endpoint), 'Expected endpoint IPv4 address or DNS name');
  const port = Number(options.port ?? config.port), mtu = Number(options.mtu ?? 1200);
  check(Number.isInteger(port) && port > 0 && port <= 65535, 'Invalid port');
  check(Number.isInteger(mtu) && mtu >= 576 && mtu <= 9000, 'Invalid MTU');
  const clientKeys = new Map();
  for (const file of readdirSync(options.keys).filter(f => f.endsWith('.key'))) {
    const key = readFileSync(join(options.keys, file), 'utf8').trim(), pub = publicKey(key);
    check(!clientKeys.has(pub), 'Duplicate client private key');
    const name = basename(file, '.key');
    check(/^[a-zA-Z0-9_-]{1,32}$/.test(name), 'Unsafe client key filename');
    clientKeys.set(pub, { privateKey: key, name });
  }
  for (const peer of config.peers) {
    const key = clientKeys.get(peer.publicKey);
    check(key, `Missing matching client private key for ${peer.address}`);
    Object.assign(peer, key);
  }
  check(existsSync(options.db), 'Initialize wg-easy first, then stop its container');
  const db = new DatabaseSync(options.db, { readOnly: !options.apply });
  try {
    check(db.prepare('PRAGMA integrity_check').get().integrity_check === 'ok', 'Database integrity check failed');
    check(db.prepare('SELECT count(*) AS n FROM __drizzle_migrations').get().n === 8, 'Unsupported database version; expected wg-easy 15.4.0');
    check(db.prepare('SELECT setup_step FROM general_table').get()?.setup_step === 0, 'Finish admin setup before importing');
    check(db.prepare('SELECT count(*) AS n FROM clients_table').get().n === 0, 'Destination already has clients; refusing to overwrite');
    check(db.prepare('SELECT count(*) AS n FROM interfaces_table').get().n === 1 && db.prepare("SELECT name FROM interfaces_table WHERE name='wg0'").get(), 'Expected a single wg0 interface');
    const admin = db.prepare('SELECT id FROM users_table WHERE enabled=1 AND role=1 ORDER BY id LIMIT 1').get();
    check(admin, 'No enabled administrator');
    const summary = { apply: Boolean(options.apply), peers: config.peers.map(p => ({ name: p.name, address: p.address })), subnet: config.cidr, endpoint: options.endpoint, port, mtu };
    if (!options.apply) return summary;
    check(options.stopped, 'Pass --stopped after stopping the wg-easy container');
    const backup = `${options.db}.before-import-${Date.now()}`;
    db.exec(`VACUUM INTO '${backup.replaceAll("'", "''")}'`); chmodSync(backup, 0o600);
    db.exec('PRAGMA foreign_keys=ON; BEGIN IMMEDIATE');
    try {
      db.prepare(`UPDATE interfaces_table SET private_key=?,public_key=?,ipv4_cidr=?,port=?,mtu=?,device='eth0',routing_table='auto',firewall_enabled=0 WHERE name='wg0'`)
        .run(config.privateKey, config.publicKey, config.cidr, port, mtu);
      db.prepare(`UPDATE user_configs_table SET host=?,port=?,default_mtu=?,default_persistent_keepalive=25,default_dns='["1.1.1.1","1.0.0.1"]',default_allowed_ips='["0.0.0.0/0"]' WHERE id='wg0'`)
        .run(options.endpoint, port, mtu);
      db.prepare(`UPDATE hooks_table SET pre_up=?,post_up='',pre_down='',post_down=? WHERE id='wg0'`)
        .run('/bin/sh /opt/wg-easy/firewall.sh up wg0 {{ipv4Cidr}} eth0', '/bin/sh /opt/wg-easy/firewall.sh down wg0 {{ipv4Cidr}} eth0');
      const insert = db.prepare(`INSERT INTO clients_table (user_id,interface_id,name,ipv4_address,ipv6_address,private_key,public_key,pre_shared_key,server_allowed_ips,allowed_ips,persistent_keepalive,mtu,enabled,server_endpoint) VALUES (?,'wg0',?,?,?,?,?,?,'[]','["0.0.0.0/0"]',25,?,1,?)`);
      config.peers.forEach((p, i) => insert.run(admin.id, p.name, p.address, `fdcc:ad94:bacf:61a4::cafe:${(i + 2).toString(16)}`, p.privateKey, p.publicKey, p.preSharedKey, mtu, options['forget-endpoints'] ? null : p.endpoint));
      check(db.prepare('PRAGMA foreign_key_check').all().length === 0, 'Foreign key check failed');
      db.exec('COMMIT');
    } catch (error) { db.exec('ROLLBACK'); throw error; }
    return { ...summary, backup };
  } finally { db.close(); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const { values } = parseArgs({ options: {
      db: { type: 'string', default: '/etc/wireguard/wg-easy.db' }, config: { type: 'string', default: '/migration/server.conf' },
      keys: { type: 'string', default: '/migration/keys' }, address: { type: 'string' }, endpoint: { type: 'string' },
      port: { type: 'string' }, mtu: { type: 'string', default: '1200' }, apply: { type: 'boolean' }, stopped: { type: 'boolean' }, 'forget-endpoints': { type: 'boolean' },
    } });
    check(values.address && values.endpoint, 'Required: --address SERVER_IP/PREFIX --endpoint PUBLIC_HOST');
    console.log(JSON.stringify(importDatabase(values), null, 2));
  } catch (error) {
    console.error(`Import refused: ${error.message}`); process.exitCode = 1;
  }
}
