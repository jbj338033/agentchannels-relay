# Agent instructions

## Purpose and boundary

This repository is a standalone Rust 2021 library and binary crate. It is the
transport-only relay used by AgentChannels: it authenticates local installations,
stores Binding routing metadata, and forwards webhook requests over WebSocket.
It does not execute agents, interpret Slack or Linear events, make access
decisions, or verify provider signatures.

## Security and compatibility invariants

- Webhook headers and bodies exist only in request/connection memory. Never
  persist or log webhook content.
- SQLite stores installation Ed25519 public keys, Binding routing metadata, and
  timestamps only.
- WebSocket authentication is an Ed25519 challenge/response. Keep protocol `1`,
  camelCase wire fields, and the `linear`/`slack` connector allowlist stable.
- Unknown connectors or Bindings return HTTP 404.
- A known Binding with no active installation connection, or one that times out,
  returns HTTP 200 and drops the event; it must never become delayed work.
- The default listener is loopback and the binary has no TLS. Public deployment
  requires an edge TLS/rate-limit boundary and exactly one enrollment policy.
  Provider signatures are verified by the local AgentChannels installation.
- Protocol changes must be coordinated with the `agentchannels` repository and
  tested against both implementations.
- Release notes must state the component version, supported protocol, schema
  impact, and rollback requirements. Publication compatibility uses an exact
  candidate client commit plus every available exact stable counterpart; never
  treat a missing artifact as a passed pairing.

## Commands

From this repository:

```sh
cargo fmt --all
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --locked
cargo build --release --locked
docker build --pull -t agentchannels-relay:test .
docker compose -f compose.yml config --quiet
docker compose -f compose.yml -f compose.build.yml config --quiet
docker compose -f compose.yml -f compose.build.yml up --build -d
docker compose -f compose.yml -f compose.build.yml down --volumes
```

Run the binary with `cargo run --release --locked`. `AGENTCHANNELS_RELAY_BIND` defaults
to `127.0.0.1:8787`; `AGENTCHANNELS_RELAY_DATABASE` defaults to
`agentchannels-relay.db`.

Enrollment startup requires exactly one of `AGENTCHANNELS_RELAY_ENROLLMENT_TOKEN`,
`AGENTCHANNELS_RELAY_ENROLLMENT_TOKEN_FILE`, or
`AGENTCHANNELS_RELAY_ALLOW_OPEN_ENROLLMENT=true`. Compose mounts the token-file
policy as `/run/secrets/relay_enrollment_token`; edge rate limiting remains a
deployment concern for public installations.

Compose uses `./secrets/relay-enrollment-token` as its enrollment secret file;
copy the example file there and replace it with an operator-controlled value
before starting a production instance. Migration backups are restored
only by an operator after preserving the current database and explicitly
acknowledging post-backup data loss; the Relay has no down-migration path.

## Change-specific verification

Add focused tests for authentication, Binding ownership and routing, persistence
boundaries, offline/timeout behavior, and wire-format changes. Run the focused
tests first, then all applicable commands above before claiming completion.
