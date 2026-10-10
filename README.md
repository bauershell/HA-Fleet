# ha-fleet — Home Assistant Fleet Manager

Rust control plane + edge agent for managing a fleet of Home Assistant instances
over a single outbound mTLS WebSocket tunnel.

Spec set: `/Users/manuel/Workspace/Private/HAFM/ha-fleet-spec/` (00–06).
This workspace implements **Phases 0–5** of `06-roadmap.md` as a verified,
runnable skeleton (every phase compiles, is unit-tested, and has an E2E demo).

## What's implemented, by phase

| Phase | Capability | Where |
|---|---|---|
| **0** Walking skeleton | enrollment (claim-code → signed cert → pinned fp), steady-state tunnel, capability detection, read ops (`states.get`, `dashboard.list/get`) | all crates |
| **1** Core management | write ops (`dashboard.save`, `automation.save`, `core.restart`), `config.check`, `health.get`, `log.stream`; **offline write queue** w/ idempotency + reconnect replay; **fail-fast reads**; **append-only audit log** | `relay/{queue,audit}.rs` |
| **2** Supervisor + backups | Supervisor broker; `backup.*`, `update.*`, `user.*`; **capability gating** (Container refuses `supervisor.*` with `capability_missing`) | `agent/broker.rs`, relay `capability_gate` |
| **3** Templates + bulk + collection | versioned templates, **bulk push + reconcile** across the fleet, central **log collector** w/ fleet-wide search | `relay/{templates,collector}.rs` |
| **4** Reverse proxy | identity-aware proxy: **default-deny grants**, short-TTL single-consume `proxy_token`, authorize-in-cloud → `proxy.open` → agent dials HA UI | `relay/proxy.rs`, agent `proxy_open` |
| **5** Critical-path hardening | **self-update** A/B slots + signature check + health gate + **watchdog rollback**; mTLS cert **rotation**; **revoke** (tunnel refused) | `agent/update.rs`, relay P5 handlers |

## Layout

```
crates/
  hafm-proto/   shared wire types: frames, enrollment, RPC envelope, op names, capabilities
  relay/        the hub + control-plane stand-in:
                  ca.rs         dev CA (signs CSRs, pins fingerprints)
                  registry.rs   instances + tunnel routing + rotation/revoke
                  tunnel.rs     enroll + steady-state handlers, RPC correlation, queue replay
                  queue.rs      offline write queue + idempotency
                  audit.rs      append-only audit log
                  templates.rs  versioned templates + push jobs + reconcile
                  collector.rs  central log collection + fleet search
                  proxy.rs      IAP grants + short-TTL proxy tokens
                  main.rs       operator HTTP API wiring all of the above
  agent/        edge agent: tunnel client, Core + Supervisor brokers,
                capability detection, self-update state machine
  mock-ha/      stand-in HA Core (REST + WS) + optional mock Supervisor + mock UI
  relay/src/store/  storage abstraction: async traits + in-memory default + pg.rs (sqlx)
migrations/     0001–0005: the full Postgres schema (04-data-model.md), wired via sqlx
```

## Build & run (Rust >= 1.75; the repo pins `stable` via rust-toolchain.toml)

```sh
cargo build && cargo test        # 31 unit tests across the workspace

# one-shot all-phases E2E (builds, boots the fleet, asserts every phase):
cargo xtask e2e

# feature matrix (all build clean):
#   (default)            in-memory store, single relay
#   --features postgres  sqlx/Postgres backend
#   --features redis     multi-relay presence routing
#   --features postgres,redis

# base E2E (one agent):
cargo run -p mock-ha             # :8123 fake HA (set MOCK_SUPERVISOR=1 for haos sim)
cargo run -p relay               # :8443 agent-facing, :8080 operator HTTP
cargo run -p agent -- enroll --claim-code DEV-CLAIM-0001
cargo run -p agent               # steady state

# operator API (control-plane stand-in), by phase:
curl localhost:8080/instances                               # P0 status
curl localhost:8080/instances/<id>/states                   # P0 read
curl -XPOST .../instances/<id>/dashboards/lovelace/save -d@cfg.json   # P1 write (queues if offline)
curl .../instances/<id>/audit                               # P1 audit
curl .../instances/<id>/backups                             # P2 (409 on Container, 200 on haos)
curl -XPOST .../templates -d '{"kind":"dashboard",...}'     # P3 template
curl -XPOST .../templates/<tid>/push -d '{"all":true}'      # P3 bulk + reconcile
curl .../logs/search?q=error                                # P3 fleet log search
curl -XPOST .../grants -d '{"principal":"a","instance_id":"<id>","scope":{"proxy":true}}'
curl -XPOST .../instances/<id>/proxy/open -d '{"principal":"a"}'      # P4 (403 w/o grant)
curl -XPOST .../instances/<id>/agent/update -d '{"version":"0.2.0","health_ok":true}'  # P5
curl -XPOST .../instances/<id>/revoke                       # P5 revoke
```

### Storage backend: in-memory (default) or Postgres

The relay runs on an in-memory store by default — **zero external deps**, the
whole skeleton + E2E runs with nothing but `cargo`. To run against real
Postgres, build with the `postgres` feature and point it at a database; sqlx
connects the pool and applies `migrations/0001–0005` on startup:

```sh
# a disposable Postgres (podman/docker), loopback-only:
podman run -d --name hafleet-pg -e POSTGRES_PASSWORD=hafleet \
  -e POSTGRES_USER=hafleet -e POSTGRES_DB=hafleet \
  -p 127.0.0.1:5433:5432 postgres:16-alpine

export DATABASE_URL="postgres://hafleet:hafleet@127.0.0.1:5433/hafleet"
cargo run -p relay --features postgres -- --store postgres
```

The same operator API, tunnel, enrollment and offline-queue semantics work
identically on either backend — the handlers call `store::*Store` trait objects
and never know which backend is behind them. `relay/src/store/mod.rs` holds the
traits + bundle; `relay/src/store/pg.rs` the sqlx impls (runtime query API, so
the crate compiles with no DB and no `.sqlx` cache). Proxy tokens are stored
**hashed** (`05 §4`); the live tunnel routing table stays process-local on both
backends (a socket is not a row — multi-relay routing is Redis pub/sub, a
scale-out item, `SECURITY-TODO` #15).

## Honesty: this is a skeleton, not a hardened build

The security **boundary** is now real across the board. **Transport is real
mTLS** — the relay serves WSS with client-cert verification, the agent generates
its keypair + CSR locally (private key never leaves the box) and presents its
CA-signed cert on every tunnel, authenticated by the fingerprint pinned at
enrollment; the CA persists across restarts (#1–#6). **Persistence is real** —
sqlx/Postgres behind `--features postgres`, verified against a live PG16 (#14).
And the latest hardening pass closed the rest:

- **#8 self-provisioning** — `agent enroll --owner-token` mints a dedicated
  least-privilege HA token and discards the owner credential.
- **#9 claim-code TTL + revocation** — codes expire and can be revoked
  (`POST /claims/:code/revoke`).
- **#11 proxy byte-streaming** — `proxy.open` streams the body as ordered base64
  `Chunk` frames + an `End` marker (real `chan=proxy` semantics).
- **#12 real A/B self-update** — on-disk slot write + `current` symlink flip +
  symlink rollback on a failed health gate.
- **#13 OIDC session principal** — the proxy derives its principal from a
  verified `Authorization: Bearer` session (`POST /auth/login`), not the body.
- **#15 multi-relay presence** — a Redis-backed `PresenceRouter`
  (`--features redis`) tracks which node owns each tunnel (presence done;
  cross-node RPC forwarding is the remaining scale-out step).

What remains is the production crust, not skeleton stubs: a Secret-Manager/HSM
CA (#5 prod), a real OIDC authorization-code callback (#13 prod), the
interactive-UI leg of the proxy, a live systemd/add-on restart for #12, and
cross-node RPC forwarding for #15. It binds to loopback only and must never
touch a real HA credential as-is.

### mTLS transport

The agent-facing endpoints run over WSS with mutual TLS (`relay/src/transport.rs`,
`agent/src/tls.rs`). On first run the relay generates + persists a CA under
`--ca-dir` (default `./ca`). Enrollment needs the relay CA out-of-band:

```sh
# relay prints/persists ca/ca-cert.pem; hand it to the agent at enrollment:
cargo run -p agent -- enroll --claim-code DEV-CLAIM-0001 \
  --relay wss://127.0.0.1:8443 --relay-ca ./ca/ca-cert.pem
cargo run -p agent -- --relay wss://127.0.0.1:8443   # steady state, presents the cert
```

`/enroll` accepts a connection with no client cert yet (the agent is there to get
one; the single-use claim code is the gate). `/tunnel` **requires** a cert that
chains to the CA *and* whose fingerprint equals the enrollment pin. The `ws://`
scheme is still accepted for the loopback test harness only.
