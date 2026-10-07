const test = require('node:test');
const assert = require('node:assert/strict');
const { mkdtemp, readFile, writeFile } = require('node:fs/promises');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { APIVaultPlus } = require('../dist/apivaultplus');

const MASTER = 'correct horse battery staple master key';
const FIXED_NOW = () => new Date('2030-01-01T00:00:00.000Z');
async function fixture(now = FIXED_NOW) {
  const dir = await mkdtemp(join(tmpdir(), 'apivaultplus-'));
  const file = join(dir, 'vault.json');
  const vault = new APIVaultPlus(file, MASTER, now);
  await vault.load();
  const admin = await vault.initialize();
  return { vault, file, admin };
}

test('encrypts secrets and tokens at rest and reloads them', async () => {
  const { vault, file, admin } = await fixture();
  await vault.put(admin, 'stripe/live', 'sk_live_super_secret', { metadata: { team: 'billing' } });
  const disk = await readFile(file, 'utf8');
  assert.equal(disk.includes('sk_live_super_secret'), false);
  assert.equal(disk.includes(admin), false);
  const reloaded = new APIVaultPlus(file, MASTER, FIXED_NOW);
  await reloaded.load();
  assert.equal((await reloaded.get(admin, 'stripe/live')).value, 'sk_live_super_secret');
});

test('enforces token scopes', async () => {
  const { vault, admin } = await fixture();
  await vault.put(admin, 'service/key', 'value');
  const reader = await vault.createToken(admin, 'reader', ['secrets:read']);
  assert.equal((await vault.get(reader, 'service/key')).value, 'value');
  await assert.rejects(vault.rotate(reader, 'service/key', 'new'), error => error.code === 'AUTH');
});

test('rotates with authenticated versioning and rejects the wrong master key', async () => {
  const { vault, file, admin } = await fixture();
  await vault.put(admin, 'github/token', 'old');
  assert.equal((await vault.rotate(admin, 'github/token', 'new')).version, 2);
  assert.equal((await vault.get(admin, 'github/token')).value, 'new');
  const wrong = new APIVaultPlus(file, 'this is definitely the wrong master key');
  await wrong.load();
  await assert.rejects(wrong.get(admin, 'github/token'), error => error.code === 'INVALID');
});

test('rejects expired and revoked secrets', async () => {
  const { vault, file, admin } = await fixture();
  await vault.put(admin, 'temporary', 'value', { expiresAt: '2030-01-02T00:00:00.000Z' });
  const future = new APIVaultPlus(file, MASTER, () => new Date('2030-01-03T00:00:00.000Z'));
  await future.load();
  await assert.rejects(future.get(admin, 'temporary'), error => error.code === 'EXPIRED');
  await vault.put(admin, 'revokable', 'value');
  await vault.revoke(admin, 'revokable');
  await assert.rejects(vault.get(admin, 'revokable'), error => error.code === 'REVOKED');
});

test('detects ciphertext tampering', async () => {
  const { vault, file, admin } = await fixture();
  await vault.put(admin, 'tamper/test', 'value');
  const data = JSON.parse(await readFile(file, 'utf8'));
  data.secrets[0].ciphertext.value = Buffer.from('altered').toString('base64');
  await writeFile(file, JSON.stringify(data));
  const reloaded = new APIVaultPlus(file, MASTER);
  await reloaded.load();
  await assert.rejects(reloaded.get(admin, 'tamper/test'), error => error.code === 'INVALID');
});

test('audit events never contain secret values', async () => {
  const { vault, admin } = await fixture();
  await vault.put(admin, 'audit/key', 'never-log-this-value');
  await vault.get(admin, 'audit/key');
  assert.equal(JSON.stringify(vault.auditLog(admin)).includes('never-log-this-value'), false);
});
