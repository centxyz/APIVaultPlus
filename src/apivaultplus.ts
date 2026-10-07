import { createCipheriv, createDecipheriv, createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';

export type Scope = 'secrets:read' | 'secrets:write' | 'secrets:rotate' | 'secrets:revoke' | 'audit:read' | 'tokens:create';
export const ALL_SCOPES: Scope[] = ['secrets:read', 'secrets:write', 'secrets:rotate', 'secrets:revoke', 'audit:read', 'tokens:create'];

interface Ciphertext { iv: string; tag: string; value: string }
interface SecretRecord { name: string; version: number; ciphertext: Ciphertext; createdAt: string; updatedAt: string; expiresAt?: string; revokedAt?: string; metadata: Record<string, string> }
interface TokenRecord { id: string; label: string; hash: string; scopes: Scope[]; createdAt: string; revokedAt?: string }
export interface AuditEntry { at: string; action: string; actor: string; target?: string; outcome: 'allowed' | 'denied' }
interface VaultFile { format: 1; tokens: TokenRecord[]; secrets: SecretRecord[]; audit: AuditEntry[] }
export interface SecretMetadata { name: string; version: number; createdAt: string; updatedAt: string; expiresAt?: string; revokedAt?: string; metadata: Record<string, string> }

const emptyVault = (): VaultFile => ({ format: 1, tokens: [], secrets: [], audit: [] });
const digest = (value: string) => createHash('sha256').update(value).digest();
const storedDigest = (value: string) => digest(value).toString('hex');

export class VaultError extends Error {
  constructor(message: string, public readonly code: 'AUTH' | 'NOT_FOUND' | 'EXPIRED' | 'REVOKED' | 'INVALID') {
    super(message);
    this.name = 'VaultError';
  }
}

export class APIVaultPlus {
  private readonly key: Buffer;
  private data: VaultFile = emptyVault();

  constructor(public readonly file: string, masterKey: string, private readonly now: () => Date = () => new Date()) {
    if (masterKey.length < 32) throw new VaultError('Master key must be at least 32 characters', 'INVALID');
    this.key = digest(masterKey);
  }

  async load(): Promise<void> {
    try {
      const parsed = JSON.parse(await readFile(this.file, 'utf8')) as VaultFile;
      if (parsed.format !== 1 || !Array.isArray(parsed.tokens) || !Array.isArray(parsed.secrets) || !Array.isArray(parsed.audit)) throw new Error('unsupported data format');
      this.data = parsed;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') this.data = emptyVault();
      else throw new VaultError(`Unable to load vault: ${(error as Error).message}`, 'INVALID');
    }
  }

  async initialize(label = 'admin'): Promise<string> {
    if (this.data.tokens.length) throw new VaultError('Vault is already initialized', 'INVALID');
    const token = this.issueToken(label, ALL_SCOPES);
    await this.persist();
    return token;
  }

  async createToken(actorToken: string, label: string, scopes: Scope[]): Promise<string> {
    const actor = this.authorize(actorToken, 'tokens:create');
    if (!label.trim() || !scopes.length || scopes.some(scope => !ALL_SCOPES.includes(scope))) throw new VaultError('A label and valid scopes are required', 'INVALID');
    const token = this.issueToken(label.trim(), [...new Set(scopes)]);
    this.audit('token.create', actor.label, label, 'allowed');
    await this.persist();
    return token;
  }

  async put(actorToken: string, name: string, value: string, options: { expiresAt?: string; metadata?: Record<string, string> } = {}): Promise<SecretMetadata> {
    const actor = this.authorize(actorToken, 'secrets:write');
    this.validateName(name);
    if (!value) throw new VaultError('Secret value cannot be empty', 'INVALID');
    if (this.data.secrets.some(secret => secret.name === name)) throw new VaultError(`Secret '${name}' already exists; rotate it instead`, 'INVALID');
    const timestamp = this.now().toISOString();
    const record: SecretRecord = { name, version: 1, ciphertext: this.encrypt(name, 1, value), createdAt: timestamp, updatedAt: timestamp, ...(options.expiresAt ? { expiresAt: this.validateExpiry(options.expiresAt) } : {}), metadata: options.metadata ?? {} };
    this.data.secrets.push(record);
    this.audit('secret.create', actor.label, name, 'allowed');
    await this.persist();
    return this.metadata(record);
  }

  async get(actorToken: string, name: string): Promise<{ value: string; secret: SecretMetadata }> {
    const actor = this.authorize(actorToken, 'secrets:read');
    const record = this.findUsable(name, actor.label, 'secret.read');
    const value = this.decrypt(record);
    this.audit('secret.read', actor.label, name, 'allowed');
    await this.persist();
    return { value, secret: this.metadata(record) };
  }

  list(actorToken: string): SecretMetadata[] {
    this.authorize(actorToken, 'secrets:read');
    return this.data.secrets.map(secret => this.metadata(secret));
  }

  async rotate(actorToken: string, name: string, value: string, expiresAt?: string): Promise<SecretMetadata> {
    const actor = this.authorize(actorToken, 'secrets:rotate');
    if (!value) throw new VaultError('Secret value cannot be empty', 'INVALID');
    const record = this.findUsable(name, actor.label, 'secret.rotate');
    record.version += 1;
    record.ciphertext = this.encrypt(name, record.version, value);
    record.updatedAt = this.now().toISOString();
    if (expiresAt) record.expiresAt = this.validateExpiry(expiresAt);
    this.audit('secret.rotate', actor.label, name, 'allowed');
    await this.persist();
    return this.metadata(record);
  }

  async revoke(actorToken: string, name: string): Promise<void> {
    const actor = this.authorize(actorToken, 'secrets:revoke');
    const record = this.data.secrets.find(secret => secret.name === name);
    if (!record) throw new VaultError(`Secret '${name}' was not found`, 'NOT_FOUND');
    if (!record.revokedAt) record.revokedAt = this.now().toISOString();
    this.audit('secret.revoke', actor.label, name, 'allowed');
    await this.persist();
  }

  auditLog(actorToken: string): AuditEntry[] {
    this.authorize(actorToken, 'audit:read');
    return this.data.audit.map(entry => ({ ...entry }));
  }

  private issueToken(label: string, scopes: Scope[]): string {
    const token = `avp_${randomBytes(32).toString('base64url')}`;
    this.data.tokens.push({ id: randomUUID(), label, hash: storedDigest(token), scopes, createdAt: this.now().toISOString() });
    this.audit('token.issue', label, undefined, 'allowed');
    return token;
  }

  private authorize(token: string, scope: Scope): TokenRecord {
    const candidate = digest(token || '');
    const actor = this.data.tokens.find(item => timingSafeEqual(Buffer.from(item.hash, 'hex'), candidate));
    if (!actor || actor.revokedAt || !actor.scopes.includes(scope)) {
      this.audit('authorization', actor?.label ?? 'unknown', scope, 'denied');
      throw new VaultError(`Missing required scope: ${scope}`, 'AUTH');
    }
    return actor;
  }

  private findUsable(name: string, actor: string, action: string): SecretRecord {
    const record = this.data.secrets.find(secret => secret.name === name);
    if (!record) throw new VaultError(`Secret '${name}' was not found`, 'NOT_FOUND');
    if (record.revokedAt) { this.audit(action, actor, name, 'denied'); throw new VaultError(`Secret '${name}' is revoked`, 'REVOKED'); }
    if (record.expiresAt && new Date(record.expiresAt) <= this.now()) { this.audit(action, actor, name, 'denied'); throw new VaultError(`Secret '${name}' is expired`, 'EXPIRED'); }
    return record;
  }

  private encrypt(name: string, version: number, value: string): Ciphertext {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.key, iv);
    cipher.setAAD(Buffer.from(`${name}:${version}`));
    const encrypted = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
    return { iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), value: encrypted.toString('base64') };
  }

  private decrypt(record: SecretRecord): string {
    try {
      const decipher = createDecipheriv('aes-256-gcm', this.key, Buffer.from(record.ciphertext.iv, 'base64'));
      decipher.setAAD(Buffer.from(`${record.name}:${record.version}`));
      decipher.setAuthTag(Buffer.from(record.ciphertext.tag, 'base64'));
      return Buffer.concat([decipher.update(Buffer.from(record.ciphertext.value, 'base64')), decipher.final()]).toString('utf8');
    } catch { throw new VaultError('Secret could not be decrypted; the key or vault data is invalid', 'INVALID'); }
  }

  private validateName(name: string): void {
    if (!/^[a-zA-Z0-9][a-zA-Z0-9._/-]{0,127}$/.test(name)) throw new VaultError('Invalid secret name', 'INVALID');
  }

  private validateExpiry(value: string): string {
    const date = new Date(value);
    if (!Number.isFinite(date.getTime()) || date <= this.now()) throw new VaultError('Expiry must be a future ISO-8601 date', 'INVALID');
    return date.toISOString();
  }

  private metadata(record: SecretRecord): SecretMetadata {
    const { ciphertext: _ciphertext, ...metadata } = record;
    return metadata;
  }

  private audit(action: string, actor: string, target: string | undefined, outcome: 'allowed' | 'denied'): void {
    this.data.audit.push({ at: this.now().toISOString(), action, actor, ...(target ? { target } : {}), outcome });
  }

  private async persist(): Promise<void> {
    await mkdir(dirname(this.file), { recursive: true });
    const temporary = `${this.file}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`;
    await writeFile(temporary, `${JSON.stringify(this.data, null, 2)}\n`, { mode: 0o600 });
    await rename(temporary, this.file);
  }
}
