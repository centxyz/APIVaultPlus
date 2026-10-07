# APIVaultPlus

[![CI](https://github.com/centxyz/APIVaultPlus/actions/workflows/ci.yml/badge.svg)](https://github.com/centxyz/APIVaultPlus/actions/workflows/ci.yml)

APIVaultPlus is a local encrypted broker for API credentials. It stores secret values with AES-256-GCM authenticated encryption, authorizes operations through scoped bearer tokens, supports expiry and versioned rotation, and records an audit trail that never contains plaintext secrets.

## Features

- Authenticated encryption at rest with a user-supplied master key
- Hashed, randomly generated access tokens with least-privilege scopes
- Secret creation, retrieval, listing, rotation, expiry, and revocation
- Tamper and wrong-key detection
- Atomic, permission-restricted persistence
- Operational audit events without secret values

## Install

```bash
git clone https://github.com/centxyz/APIVaultPlus.git
cd APIVaultPlus
npm install
npm run build
```

## Quick start

Choose a strong master key and initialize a vault. The returned administrator token is shown once.

```bash
export APIVAULT_MASTER_KEY='replace-this-with-at-least-32-random-characters'
export APIVAULT_FILE="$PWD/.apivault/vault.json"
npm start -- init
export APIVAULT_TOKEN='avp_token_returned_by_init'

npm start -- put stripe/live --value 'sk_live_example' --metadata '{"team":"billing"}'
npm start -- get stripe/live
npm start -- rotate stripe/live --value 'sk_live_replacement'
npm start -- list
npm start -- audit
```

Create a read-only token for a service:

```bash
npm start -- token-create --label checkout-api --scopes secrets:read
```

Available scopes are `secrets:read`, `secrets:write`, `secrets:rotate`, `secrets:revoke`, `audit:read`, and `tokens:create`.

> This tool protects the vault file, but command-line values may be retained by your shell. In automated use, expand values from a protected environment or secret manager and restrict access to the vault file, master key, and tokens.

## Development

```bash
npm test
npm run build
```

The test suite checks encryption at rest, persistence, scoped authorization, rotation, expiry, revocation, authenticated tamper detection, wrong-key rejection, and audit-log hygiene.

## License

MIT © cent

## Current limitations

- It cannot protect secrets on a compromised host or from a process that already has the master key and a valid token.
- Shell arguments and environment variables may be exposed by the operating system or shell history.
- The project has not received a professional security audit.
