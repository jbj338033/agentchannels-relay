# AgentChannels Relay

AgentChannels Relay forwards Slack and Linear webhooks to authenticated local AgentChannels installations.

## Run locally

```sh
cargo run --release
```

From a source checkout, run with Docker Compose:

```sh
docker compose up --build -d
docker compose logs -f
docker compose down
```

## Configuration

- `AGENTCHANNELS_RELAY_BIND` sets the HTTP and WebSocket listen address. Default: `127.0.0.1:8787`.
- `AGENTCHANNELS_RELAY_DATABASE` sets the SQLite database path. Default: `agentchannels-relay.db`.

When binding beyond loopback, place the relay behind TLS and an authenticated installation-enrollment boundary.

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

Wire messages use camelCase fields. Provider webhook signatures are verified by the local AgentChannels installation.

## Development

```sh
cargo fmt --all
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --locked
cargo build --release
```
