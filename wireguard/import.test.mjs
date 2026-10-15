import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, copyFileSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { parseConfig, publicKey, importDatabase } from './import.mjs';

const serverKey = randomBytes(32).toString('base64');
const clientKey = randomBytes(32).toString('base64');
const config = `[Interface]\nPrivateKey = ${serverKey}\nListenPort = 51871\n[Peer]\nPublicKey = ${publicKey(clientKey)}\nAllowedIPs = 10.203.13.2/32\nEndpoint = 192.0.2.10:12345\n`;

test('X25519 public key agrees with wireguard-tools', () => {
  assert.equal(publicKey(serverKey), execFileSync('wg', ['pubkey'], { input: serverKey + '\n', encoding: 'utf8' }).trim());
});
test('preserves server identity, subnet and endpoint; no PSK is encoded as zero', () => {
  const parsed = parseConfig(config, '10.203.13.1/29');
  assert.equal(parsed.privateKey, serverKey);
  assert.equal(parsed.cidr, '10.203.13.0/29');
  assert.equal(parsed.peers[0].endpoint, '192.0.2.10:12345');
  assert.equal(parsed.peers[0].preSharedKey, Buffer.alloc(32).toString('base64'));
});
test('rejects hooks, routed subnets, duplicate addresses, and out-of-range clients', () => {
  assert.throws(() => parseConfig(config.replace('ListenPort', 'PostUp = do-not-run\nListenPort'), '10.203.13.1/29'), /Unsupported field/);
  assert.throws(() => parseConfig(config.replace('10.203.13.2/32', '0.0.0.0/0'), '10.203.13.1/29'), /exactly one/);
  assert.throws(() => parseConfig(config + config.slice(config.indexOf('[Peer]')), '10.203.13.1/29'), /Duplicate peer/);
  assert.throws(() => parseConfig(config.replace('10.203.13.2/32', '10.203.13.7/32'), '10.203.13.1/29'), /usable client range/);
});

// Provide a stopped, initialized, empty wg-easy 15.4.0 database. Tests copy it.
const baseline = process.env.WG_TEST_DB;
function fixture() {
  assert.ok(baseline, 'WG_TEST_DB must reference a stopped initialized database');
  const root = mkdtempSync(join(tmpdir(), 'wg-import-test-'));
  const options = { db: join(root, 'test.db'), config: join(root, 'server.conf'), keys: join(root, 'keys'), address: '10.203.13.1/29', endpoint: 'vpn.example.com' };
  mkdirSync(options.keys);
  copyFileSync(baseline, options.db);
  writeFileSync(options.config, config);
  writeFileSync(join(options.keys, 'client.key'), clientKey);
  return { root, options };
}
test('dry run leaves DB unchanged; apply preserves keys and backup; repeat is refused', () => {
  const { root, options } = fixture();
  try {
    const original = readFileSync(options.db);
    const summary = importDatabase(options);
    assert.equal(summary.peers.length, 1);
    assert.deepEqual(readFileSync(options.db), original);
    const result = importDatabase({ ...options, apply: true, stopped: true });
    const db = new DatabaseSync(options.db);
    assert.equal(db.prepare('SELECT private_key FROM interfaces_table').get().private_key, serverKey);
    const peer = db.prepare('SELECT * FROM clients_table').get();
    assert.equal(peer.private_key, clientKey);
    assert.equal(peer.server_endpoint, '192.0.2.10:12345');
    db.close();
    const backup = new DatabaseSync(result.backup);
    assert.equal(backup.prepare('SELECT count(*) n FROM clients_table').get().n, 0);
    backup.close();
    assert.throws(() => importDatabase({ ...options, apply: true, stopped: true }), /already has clients/);
  } finally { rmSync(root, { recursive: true }); }
});
test('a DB failure rolls back server identity and all peer changes', () => {
  const { root, options } = fixture();
  try {
    const db = new DatabaseSync(options.db);
    const originalKey = db.prepare('SELECT private_key FROM interfaces_table').get().private_key;
    db.exec("CREATE TRIGGER reject_import BEFORE INSERT ON clients_table BEGIN SELECT RAISE(ABORT, 'test failure'); END");
    db.close();
    assert.throws(() => importDatabase({ ...options, apply: true, stopped: true }), /test failure/);
    const after = new DatabaseSync(options.db);
    assert.equal(after.prepare('SELECT private_key FROM interfaces_table').get().private_key, originalKey);
    assert.equal(after.prepare('SELECT count(*) n FROM clients_table').get().n, 0);
    after.close();
  } finally { rmSync(root, { recursive: true }); }
});
test('missing client key and missing stop acknowledgement cannot change the DB', () => {
  const { root, options } = fixture();
  try {
    const original = readFileSync(options.db);
    assert.throws(() => importDatabase({ ...options, apply: true }), /--stopped/);
    writeFileSync(join(options.keys, 'client.key'), randomBytes(32).toString('base64'));
    assert.throws(() => importDatabase({ ...options, apply: true, stopped: true }), /Missing matching/);
    assert.deepEqual(readFileSync(options.db), original);
  } finally { rmSync(root, { recursive: true }); }
});
