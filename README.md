# key-connector

A small key connector for [Vaultwarden](https://github.com/dani-garcia/vaultwarden),
compatible with the Bitwarden clients.

For SSO organizations that use a key connector, users have no master password. The
master key is stored here instead and fetched by the client at unlock time. The service
never sees vault data or passwords, it just stores one opaque base64 blob per user,
addressed by the user id of a validated access token.

The protocol was worked out from the open source Vaultwarden (AGPL) and Bitwarden
client (GPL) code, see [docs/PROTOCOL.md](docs/PROTOCOL.md) for the details and
references. Bitwarden's own key-connector code was not used for this.

## API

| Method | Path         | Auth         | Body / Response                 |
| ------ | ------------ | ------------ | ------------------------------- |
| GET    | `/alive`     | none         | `200 OK` health check           |
| GET    | `/user-keys` | Bearer token | `200` with `{ "key": "<b64>" }` |
| POST   | `/user-keys` | Bearer token | `{ "key": "<b64>" }`, `200`     |

The bearer token is the Vaultwarden access token. It is verified with RS256 against
Vaultwarden's RSA public key, the issuer and `exp`/`nbf` must be valid, and it must
carry the `api` scope. The user is identified by the `sub` claim, so a token can
only ever read or write its own key. `POST` accepts only the base64 encoding of a
32 byte master key; anything else is rejected with `400`.

## Configuration

Everything is set via environment variables, see [`.env.example`](.env.example):

- `KC_BIND_ADDR` (default `0.0.0.0:8081`)
- `KC_DATABASE_URL` (default `sqlite://keyconnector.db?mode=rwc`) — SQLite or
  MySQL, e.g. `mysql://keyconnector:password@db:3306/keyconnector`
- `KC_IDENTITY_AUTHORITY`, e.g. `https://vault.example.com/identity` — issuer and
  signing key are fetched from its OIDC discovery document and refreshed
  periodically, nothing else to configure
- alternatively a static key: `KC_IDENTITY_PUBLIC_KEY_PATH` or
  `KC_IDENTITY_PUBLIC_KEY_PEM`, plus `KC_JWT_ISSUER`
  (e.g. `https://vault.example.com|login`)
- `KC_ENCRYPTION_KEY_PATH` or `KC_ENCRYPTION_KEY` (required), a base64 encoded
  32 byte key used to encrypt the stored keys at rest; generate one with
  `openssl rand -base64 32`
- `KC_CORS_ALLOWED_ORIGINS`, comma separated browser origins allowed to call the
  connector (your web vault origin). CORS is opt in: when unset, no browser origin
  is accepted.
- `KC_API_PREFIX`, optional path prefix when the connector is served from a
  subpath, e.g. `/kc` mounts `/kc/alive` and `/kc/user-keys`. `API_PREFIX` is
  accepted as an alias.

With a static key, export the public half of the RSA keypair Vaultwarden generates
on first start (`data/rsa_key.pem` by default):

```sh
openssl rsa -in /path/to/vaultwarden/data/rsa_key.pem -pubout -out identity.pub.pem
```

## Vaultwarden setup

Key Connector support is not merged in Vaultwarden yet, see
[PR #7419](https://github.com/dani-garcia/vaultwarden/pull/7419). Until then the
`main` branch of [acul021/vaultwarden](https://github.com/acul021/vaultwarden) has
the PR included and is built as `ghcr.io/acul021/vaultwarden:testing` (amd64 only).

Vaultwarden needs working SSO, plus:

```ini
KEY_CONNECTOR_ENABLED=true
KEY_CONNECTOR_URL=https://keyconnector.example.com
# Shown on the enrollment confirmation screen in the clients:
KEY_CONNECTOR_ORG_NAME=Example Corp
```

New SSO users are then enrolled with the connector instead of being asked to create
a master password. Existing users are offered to remove their master password on
their next SSO login.

## Build, test, run

```sh
cargo test
cargo build --release
KC_IDENTITY_AUTHORITY='https://vault.example.com/identity' \
KC_ENCRYPTION_KEY="$(openssl rand -base64 32)" \
  ./target/release/key-connector
```

Or with Docker: `docker build -t key-connector .`

## Docker Compose (production)

`docker-compose.yml` runs only the connector and points at your existing MySQL;
the encryption key is supplied as a Docker secret:

```sh
mkdir -p secrets
openssl rand -base64 32 > secrets/kc_encryption_key.txt
cp .env.compose.example .env      # edit it, then: chmod 600 .env
docker compose up -d
```

The database must already exist. On first start the connector creates its table,
so its MySQL user needs `CREATE, SELECT, INSERT, UPDATE` on that database. If you
prefer to create the table yourself and grant only `SELECT, INSERT, UPDATE`, use:

```sql
CREATE TABLE user_keys (
    user_id VARCHAR(255) NOT NULL PRIMARY KEY,
    `key`   VARCHAR(1024) NOT NULL
);
```

No MySQL `root` account is involved anywhere.

The connector is published on `127.0.0.1:8081` only; terminate TLS in the reverse
proxy in front of it. With `KC_API_PREFIX=/kc` the proxy must forward `/kc/...`
unchanged (do not strip the prefix) and the Bitwarden `keyConnectorUrl` /
`KEY_CONNECTOR_URL` becomes `https://keyconnector.example.com/kc`.

## Deployment notes

Run this behind a reverse proxy with TLS, the clients require an https connector URL
anyway and the access token and key would otherwise go over the wire in plain text.
Terminate rate limiting at the proxy too; the connector does not throttle requests.
`GET /user-keys` responses are sent with `Cache-Control: no-store`.

The stored keys are encrypted at rest with AES-256-GCM under `KC_ENCRYPTION_KEY`,
each entry bound to its user id, so a leaked database or backup is useless on its
own. Plaintext rows from older versions are encrypted once at startup.

The encryption key is as critical as the database itself: losing either one locks
the affected users out of their vaults permanently. Back both up, and keep the key
away from the database and its backups, e.g. mounted from a secret store via
`KC_ENCRYPTION_KEY_PATH`. Keeping the database on a different host than the
Vaultwarden one is still a good idea.

## License

AGPL-3.0-or-later, same as Vaultwarden.
