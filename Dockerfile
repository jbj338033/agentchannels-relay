FROM rust:1.95.0-bookworm AS builder

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim AS runtime

RUN groupadd --gid 10001 agentchannels-relay \
    && useradd --uid 10001 --gid 10001 --no-create-home \
      --home-dir /var/lib/agentchannels-relay --shell /usr/sbin/nologin \
      agentchannels-relay \
    && mkdir -p /var/lib/agentchannels-relay \
    && chown 10001:10001 /var/lib/agentchannels-relay

COPY --from=builder --chown=10001:10001 \
  /build/target/release/agentchannels-relay \
  /usr/local/bin/agentchannels-relay

ENV AGENTCHANNELS_RELAY_BIND=0.0.0.0:8787 \
    AGENTCHANNELS_RELAY_DATABASE=/var/lib/agentchannels-relay/agentchannels-relay.db

WORKDIR /var/lib/agentchannels-relay
USER 10001:10001
EXPOSE 8787

ENTRYPOINT ["/usr/local/bin/agentchannels-relay"]
