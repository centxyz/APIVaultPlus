import minimist from 'minimist';
import { APIVaultPlus, Scope, VaultError } from './apivaultplus';

const usage = `APIVaultPlus — encrypted API-secret broker

Usage:
  apivaultplus init [--label admin]
  apivaultplus token-create --label SERVICE --scopes SCOPE,SCOPE
  apivaultplus put NAME --value SECRET [--expires ISO_DATE] [--metadata JSON]
  apivaultplus get NAME
  apivaultplus list
  apivaultplus rotate NAME --value SECRET [--expires ISO_DATE]
  apivaultplus revoke NAME
  apivaultplus audit

Environment:
  APIVAULT_MASTER_KEY  Required; at least 32 characters
  APIVAULT_TOKEN       Required except for init
  APIVAULT_FILE        Optional; defaults to .apivault/vault.json`;

async function main(): Promise<void> {
  const args = minimist(process.argv.slice(2), { string: ['label', 'scopes', 'value', 'expires', 'metadata', 'file'], boolean: ['help'], alias: { h: 'help' } });
  if (args.help || !args._[0]) { console.log(usage); return; }
  const masterKey = process.env.APIVAULT_MASTER_KEY;
  if (!masterKey) throw new VaultError('APIVAULT_MASTER_KEY is required', 'INVALID');
  const vault = new APIVaultPlus(args.file || process.env.APIVAULT_FILE || '.apivault/vault.json', masterKey);
  await vault.load();
  const command = String(args._[0]);
  const name = args._[1] ? String(args._[1]) : '';
  const token = process.env.APIVAULT_TOKEN || '';
  let output: unknown;

  switch (command) {
    case 'init': output = { token: await vault.initialize(args.label || 'admin'), warning: 'Store this token securely; it cannot be recovered.' }; break;
    case 'token-create': output = { token: await vault.createToken(token, args.label || '', String(args.scopes || '').split(',').filter(Boolean) as Scope[]) }; break;
    case 'put': output = await vault.put(token, name, String(args.value || ''), { ...(args.expires ? { expiresAt: args.expires } : {}), ...(args.metadata ? { metadata: JSON.parse(args.metadata) } : {}) }); break;
    case 'get': output = await vault.get(token, name); break;
    case 'list': output = vault.list(token); break;
    case 'rotate': output = await vault.rotate(token, name, String(args.value || ''), args.expires); break;
    case 'revoke': await vault.revoke(token, name); output = { revoked: name }; break;
    case 'audit': output = vault.auditLog(token); break;
    default: throw new VaultError(`Unknown command: ${command}`, 'INVALID');
  }
  console.log(JSON.stringify(output, null, 2));
}

if (require.main === module) {
  main().catch(error => {
    console.error(JSON.stringify({ error: error instanceof Error ? error.message : String(error), code: error instanceof VaultError ? error.code : 'INTERNAL' }));
    process.exitCode = 1;
  });
}

export { main };
