# SECURITY-TODO — Phase 0 corners cut

The Phase 0 walking skeleton proves the **data path**, not the **security
boundary**. Every deviation from `05-security.md` / `03-agent-protocol.md` is
listed here so nothing ships silently. These are the gating items before any
real HA instance connects.

| # | Gap | Spec it violates | Where | Phase to fix |
|---|-----|------------------|-------|--------------|
| 1 | ~~Relay serves plain WS/HTTP~~ **DONE:** agent-facing side serves **WSS/TLS** (rustls); CA-signed relay server cert. | `03` transport = WSS/mTLS | `relay/src/transport.rs` | ✅ |
| 2 | ~~`/tunnel` does not verify the client cert~~ **DONE:** rustls verifies the client cert chains to the CA; the handler then requires its SHA-256 fingerprint to equal the one pinned at enrollment — HELLO.instance_id is now only a lookup key. | `03 §1b` cert binding is the auth | `relay/src/transport.rs` + `tunnel.rs` `handle_tunnel_tls` | ✅ |
| 3 | ~~Agent sends a placeholder CSR~~ **DONE:** agent generates a keypair + real PKCS#10 CSR locally; only the CSR is sent, the private key is stored on the box and never transmitted. | `03 §1a` agent-generated keypair + CSR | `agent/src/tls.rs` `generate_keypair_and_csr` | ✅ |
| 4 | ~~CA signs a cert not bound to the CSR key~~ **DONE:** CA parses the CSR and signs **its** public key, stamping a client-auth EKU. | `03 §1a` issued cert binds CSR key | `relay/src/ca.rs` `sign_csr` | ✅ |
| 5 | ~~Dev CA in-memory, regenerated each start~~ **DONE:** CA keypair persisted to `--ca-dir` (generated first run, loaded thereafter), so issued certs stay verifiable across restarts. Secret-Manager/HSM backing is the production step. | `05 §2`, `02 §4` Secret Manager | `relay/src/ca.rs` `load_or_generate` | ✅ (SM = prod) |
| 6 | ~~Agent connects without presenting its cert~~ **DONE:** steady-state `/tunnel` connects with a rustls client config presenting the issued cert + key — real mutual TLS. | `03 §1b` | `agent/src/tls.rs` `connector_tunnel` | ✅ |
| 7 | mock-ha **accepts any token**; no HA auth enforced | n/a (test harness) | `mock-ha/src/main.rs` | — (harness only) |
| 8 | ~~HA token is a dev placeholder; no self-provisioning~~ **DONE:** `agent enroll --owner-token` self-provisions a dedicated least-privilege HA token (`05 §2.1`); the owner credential is used once and never stored. Stored dedicated token used for all steady-state HA calls. | `05 §2.1` owner-cred-once-then-discard | `agent` enroll + `mock-ha` `/auth/provision` | ✅ |
| 9 | ~~Claim codes have no TTL/revocation~~ **DONE:** claim codes carry a TTL (default 1h) and a revocation flag; `consume_claim` rejects unknown/spent/revoked/expired. Operator `POST /claims/:code/revoke`; migration 0006 adds the column for the PG backend. | `05 §2` short-TTL, revocable | `relay/src/registry.rs` + `store/pg.rs` | ✅ |
| 10 | ~~No audit log~~ **DONE (Phase 1):** append-only audit log of every op | `05 §6`, `04 §7` | `relay/src/audit.rs` | ✅ 1 |
| 11 | ~~Reverse proxy fetches HA UI once~~ **DONE:** `proxy.open` streams the response body back as an ordered sequence of base64 `Chunk` frames terminated by an `End` marker — the real `chan=proxy` byte-stream semantics. Full bidirectional interactive-UI tunnelling rides the same framing (remaining integration). | `03 §6` byte stream | `agent/src/broker.rs` `proxy_open` | ✅ |
| 12 | ~~Self-update simulates the flip~~ **DONE:** real on-disk A/B slot swap — writes the new binary to the inactive slot, flips a `current` symlink, health-gates, and rolls the symlink back on failure. Wiring a live systemd/add-on restart of `current` is the deploy-env step. | `05 §5.2` | `agent/src/update.rs` `SlotLayout` | ✅ |
| 13 | ~~Proxy principal from the request body~~ **DONE:** real **OIDC authorization-code + PKCE** flow (`/auth/start` → IdP → `/auth/callback`) verifies the `id_token` JWT against the IdP's JWKS (sig + `iss`/`aud`/`exp`), maps groups→role (email fallback for the dev IdP), and mints an httpOnly session cookie. Bundled **Dex** is the dev IdP; a real IdP is a config swap (`OIDC_ISSUER`). Plus **RBAC**: Viewer/Operator/Admin roles enforced per endpoint by extractors (`rbac.rs`); destructive ops are Admin-only. Dev `/auth/login` stays behind `--dev-auth` for curl/tests. | `04 §8`, `05 §3/§6`, FR-5 | `relay/src/oidc.rs` + `rbac.rs` + `sessions.rs`; `deploy/dex-config.yaml` | ✅ (external IdP = prod swap) |
| 14 | ~~No real Postgres; in-memory stores~~ **DONE:** `sqlx`/Postgres backend behind the `postgres` feature; all 6 stores + `migrations/0001–0006` wired & verified against a live PG16. In-memory stays the zero-dep default (`--store memory`). | `04` | `relay/src/store/` | ✅ |
| 15 | ~~Routing table process-local; no multi-relay~~ **PARTIAL:** presence layer DONE — a Redis-backed `PresenceRouter` (`--features redis --redis-url`) registers which node owns each tunnel with a heartbeat-refreshed TTL, verified against live Redis (`/instances/:id/owner`). Default is a single-node local no-op. Cross-node RPC **forwarding** (pub/sub the request to the owning node) rides on this map and is the remaining scale-out integration. | `02 §1.2` | `relay/src/routing.rs` | ◑ presence done |

## Posture statement

Phase 0 is a **local dev skeleton bound to loopback** (`127.0.0.1`). It must not
be exposed on a routable interface, and no production HA credential should ever
be given to it. Items 1–6 together are the real mTLS enrollment boundary and are
the headline of **Phase 5 — critical-path hardening** (`06-roadmap.md`); items
8–10 are earlier because Phase 1 needs real persistence + audit.
