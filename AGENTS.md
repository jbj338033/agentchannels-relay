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
- The default listener is loopback. The binary has no TLS and
  `POST /v1/installations` has no administrator authentication. Provider
  signatures are verified by the local AgentChannels installation. Do not
  describe this service as safe for direct public exposure.
- Protocol changes must be coordinated with the `agentchannels` repository and
  tested against both implementations.

## Commands

From this repository:

```sh
cargo fmt --all
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --locked
cargo build --release
docker build --pull -t agentchannels-relay:test .
docker compose config --quiet
docker compose up --build -d
docker compose down --volumes
```

Run the binary with `cargo run --release`. `AGENTCHANNELS_RELAY_BIND` defaults
to `127.0.0.1:8787`; `AGENTCHANNELS_RELAY_DATABASE` defaults to
`agentchannels-relay.db`.

## Change-specific verification

Add focused tests for authentication, Binding ownership and routing, persistence
boundaries, offline/timeout behavior, and wire-format changes. Run the focused
tests first, then all applicable commands above before claiming completion.
