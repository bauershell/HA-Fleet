# ha-fleet dev image — builds relay (postgres+redis), agent, mock-ha once and
# ships all three binaries. The compose file runs one service per binary.
#
# Multi-stage: a cargo builder, then a slim debian runtime with just the bins.

FROM rust:1-slim-bookworm AS builder
WORKDIR /src
# System deps for building (sqlx/rustls use ring; nothing extra needed beyond
# a C toolchain which the rust image already has).
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY migrations ./migrations
COPY xtask ./xtask
# Build the relay with the postgres + redis features; agent + mock-ha plain.
RUN cargo build --release -p relay --features postgres,redis \
 && cargo build --release -p agent -p mock-ha

FROM debian:bookworm-slim AS runtime
# ca-certificates for any outbound TLS; curl for container healthchecks.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /src/target/release/relay   /usr/local/bin/relay
COPY --from=builder /src/target/release/agent   /usr/local/bin/agent
COPY --from=builder /src/target/release/mock-ha /usr/local/bin/mock-ha
# Non-root for good measure; /data is where the CA + agent identity live.
RUN useradd -m -u 10001 hafleet && mkdir -p /data && chown -R hafleet /data
USER hafleet
ENV RUST_LOG=info
# Default command is overridden per-service in the compose file.
CMD ["relay"]
