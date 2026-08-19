# AgentChannels Relay

AgentChannels Relay forwards Slack and Linear webhooks to authenticated local AgentChannels installations.

## Run locally

```sh
cargo run --release --locked
```

From a source checkout, run with Docker Compose:

```sh
docker compose -f compose.yml -f compose.build.yml up --build -d
docker compose logs -f
docker compose down
```

## Configuration

- `AGENTCHANNELS_RELAY_BIND` sets the HTTP and WebSocket listen address. Default: `127.0.0.1:8787`.
- `AGENTCHANNELS_RELAY_DATABASE` sets the SQLite database path. Default: `agentchannels-relay.db`.
- Exactly one enrollment policy is required: `AGENTCHANNELS_RELAY_ENROLLMENT_TOKEN`, `AGENTCHANNELS_RELAY_ENROLLMENT_TOKEN_FILE`, or `AGENTCHANNELS_RELAY_ALLOW_OPEN_ENROLLMENT=true`. The file policy is the production Compose path; open enrollment is for controlled development only.
- Compose reads `./secrets/relay-enrollment-token`. Copy `secrets/relay-enrollment-token.example` to that path, replace its contents with an operator-controlled token, and keep the file out of version control.
- Persistent migrations create a SQLite-backup artifact under `/var/lib/agentchannels-relay/backups` (or beside a development database) before changing schema. Backups are operator-only and are never automatically pruned.

When binding beyond loopback, place the relay behind TLS, edge rate limiting, and an authenticated installation-enrollment boundary. The binary does not terminate public TLS.

## Endpoints

- `POST /v1/installations` registers an installation ID and Ed25519 public key. Re-registering the same key is idempotent; a different key for the same ID returns `409 Conflict`.
- `GET /v1/connect` upgrades to WebSocket and authenticates an installation with an Ed25519 challenge.
- `POST /v1/webhooks/{connector}/{binding}` forwards a webhook through the stored Binding route. Only `linear` and `slack` connectors are accepted; unknown connectors or Bindings return `404 Not Found`.

For a known Binding, an offline installation or a response timeout returns `200 OK` and drops the event. Request headers and the base64-encoded raw body are forwarded in memory and webhook content is not persisted.

## Protocol flow

1. The local installation registers its public key with `POST /v1/installations`.
2. It opens `/v1/connect`, signs the relay's nonce, and sends `authenticate`.
3. After `authenticated`, it sends `sync_bindings` with its `bindingId` and connector pairs.
4. The relay sends protocol-v1 `webhook` messages and returns each `webhook_response` status, headers, and body to the HTTP caller.

Messages with a protocol other than `1` receive an explicit `unsupported_protocol` error. Unknown messages receive `invalid_message`; incompatible messages are never silently ignored.

Wire messages use camelCase fields. Provider webhook signatures are verified by the local AgentChannels installation.

## Development

```sh
cargo fmt --all
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --locked
cargo build --release --locked
```

The released `compose.yml` fixes the official GHCR image to the same full version as the source release. Use the Compose file from a different release when upgrading or rolling back; the default never follows a mutable tag.

### Restore a migration backup

Stop the relay and preserve the current database before restoring the named
backup. Restoration is operator-initiated and never runs a down-migration:

```sh
docker compose stop relay
docker compose run --rm --no-deps --entrypoint sh relay -c \
  'target=/var/lib/agentchannels-relay/pre-restore-$(date -u +%Y%m%dT%H%M%SZ); mkdir "$target" && cp /var/lib/agentchannels-relay/agentchannels-relay.db* "$target"/'
docker compose run --rm --no-deps \
  -e ACK_POST_BACKUP_DATA_LOSS=I_UNDERSTAND_POST_BACKUP_DATA_LOSS \
  --entrypoint sh relay -c \
  'test "$ACK_POST_BACKUP_DATA_LOSS" = I_UNDERSTAND_POST_BACKUP_DATA_LOSS && rm -f /var/lib/agentchannels-relay/agentchannels-relay.db-wal /var/lib/agentchannels-relay/agentchannels-relay.db-shm && cp /var/lib/agentchannels-relay/backups/<component-version-schema-timestamp>.sqlite3 /var/lib/agentchannels-relay/agentchannels-relay.db'
docker compose up -d relay
```

The acknowledgment is required because writes made after the backup may be
lost. Select the backup by its component version, source schema, and timestamp.
