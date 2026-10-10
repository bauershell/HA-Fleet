//! `relay` — the tunnel hub + operator entry point for Phase 0 (`02 §1.1/1.2`).
//!
//! Two surfaces:
//!   * **agent-facing** (`:8443`): `/enroll` (one-time, `03 §1a`) and `/tunnel`
//!     (steady state, `03 §1b`), both WebSocket.
//!   * **operator-facing** (`:8080`): a tiny HTTP API standing in for the
//!     control plane + frontend — list instances and issue the Phase 0 read ops.
//!
//! ⚠️ Phase 0 runs both as **plain WS/HTTP** (no TLS termination here). The spec
//! calls for WSS + mTLS on the agent side; wiring rustls + client-cert
//! verification is Phase 5 hardening (`SECURITY-TODO.md`). The enrollment
//! message flow and cert issuance are real; the transport encryption is stubbed.

mod audit;
mod ca;
mod collector;
mod oidc;
mod proxy;
mod queue;
mod rbac;
mod registry;
mod routing;
mod sessions;
mod store;
mod templates;
mod transport;
mod tunnel;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use uuid::Uuid;

use ca::DevCa;
use registry::EnrollState;
use store::{
    AuditStore, CollectorStore, ProxyStore, QueueStore, RegistryStore, StoreBackend, TemplateStore,
};
use templates::{JobState, TemplateKind};
use tunnel::Hub;

#[derive(Parser, Debug)]
#[command(name = "relay", about = "ha-fleet relay/tunnel hub")]
struct Args {
    /// Agent-facing bind (enroll + tunnel). Loopback-only.
    #[arg(long, env = "RELAY_AGENT_BIND", default_value = "127.0.0.1:8443")]
    agent_bind: String,
    /// Operator-facing HTTP bind.
    #[arg(long, env = "RELAY_OP_BIND", default_value = "127.0.0.1:8080")]
    op_bind: String,
    /// A dev claim code seeded at startup so the walk needs no operator UI.
    #[arg(long, env = "RELAY_DEV_CLAIM", default_value = "DEV-CLAIM-0001")]
    dev_claim: String,
    /// Storage backend: `memory` (default, zero deps) or `postgres`
    /// (requires `--features postgres` at build + DATABASE_URL at runtime).
    #[arg(long, env = "RELAY_STORE", default_value = "memory")]
    store: StoreBackend,
    /// Postgres connection URL (used only with `--store postgres`).
    #[arg(long, env = "DATABASE_URL")]
    database_url: Option<String>,
    /// Directory the CA keypair is persisted to (generated on first run,
    /// loaded thereafter) so issued client certs stay verifiable across
    /// restarts (SECURITY-TODO #5).
    #[arg(long, env = "RELAY_CA_DIR", default_value = "./ca")]
    ca_dir: PathBuf,
    /// Redis URL for multi-relay presence routing (SECURITY-TODO #15). Requires
    /// building with `--features redis`. Omit for a single-node local router.
    #[arg(long, env = "RELAY_REDIS_URL")]
    redis_url: Option<String>,
    /// OIDC issuer URL (e.g. the bundled Dex at http://dex:5556/dex). When set,
    /// the relay runs the real auth-code+PKCE browser flow (SECURITY-TODO #13).
    #[arg(long, env = "OIDC_ISSUER")]
    oidc_issuer: Option<String>,
    /// Container-reachable base for the OIDC back-channel (discovery/token/JWKS)
    /// when it differs from the browser-facing issuer. Defaults to the issuer.
    #[arg(long, env = "OIDC_DISCOVERY_BASE")]
    oidc_discovery_base: Option<String>,
    /// OIDC relying-party client id (registered with the IdP).
    #[arg(long, env = "OIDC_CLIENT_ID", default_value = "ha-fleet")]
    oidc_client_id: String,
    /// OIDC client secret.
    #[arg(long, env = "OIDC_CLIENT_SECRET", default_value = "")]
    oidc_client_secret: String,
    /// Redirect URI registered with the IdP (the relay's /auth/callback).
    #[arg(long, env = "OIDC_REDIRECT_URI", default_value = "http://127.0.0.1:8080/auth/callback")]
    oidc_redirect_uri: String,
    /// Keep the dev `/auth/login` (trusts a posted principal, no IdP). On by
    /// default so curl + `start.sh test` work; set --no-dev-auth to require OIDC.
    #[arg(long, env = "RELAY_DEV_AUTH", default_value = "true", action = clap::ArgAction::Set)]
    dev_auth: bool,
    /// Optional directory of the built SPA. When set, the relay serves it on the
    /// operator port so the UI is SAME-ORIGIN with the API (the session cookie
    /// then rides along; a split-port dev server cannot send a SameSite cookie).
    #[arg(long, env = "RELAY_FRONTEND_DIR")]
    frontend_dir: Option<PathBuf>,
}

/// The relay's shared state. Stores are trait objects (`store::*Store`) so the
/// backend (in-memory default or sqlx/Postgres behind the `postgres` feature)
/// is a construction-time choice, not a type the handlers know about.
#[derive(Clone)]
pub struct AppState {
    pub registry: Arc<dyn RegistryStore>,
    pub hub: Arc<Hub>,
    pub ca: Arc<DevCa>,
    pub audit: Arc<dyn AuditStore>,
    pub queue: Arc<dyn QueueStore>,
    pub templater: Arc<dyn TemplateStore>,
    pub collector: Arc<dyn CollectorStore>,
    pub proxy_authz: Arc<dyn ProxyStore>,
    /// Operator OIDC session store (SECURITY-TODO #13): the proxy derives its
    /// principal from a verified session, not a request-body field. Relay-local.
    pub sessions: Arc<sessions::SessionStore>,
    /// Multi-relay presence router (SECURITY-TODO #15): which node owns each
    /// instance's tunnel. Local no-op by default; Redis-backed with `--redis-url`.
    pub router: Arc<dyn routing::PresenceRouter>,
    /// OIDC relying-party config (SECURITY-TODO #13), present when --oidc-issuer
    /// is set and discovery succeeded. None → OIDC routes return 501.
    pub oidc: Option<Arc<oidc::OidcConfig>>,
    /// In-flight OIDC auth-code+PKCE attempts (state → verifier), short TTL.
    pub auth_flights: Arc<oidc::AuthFlights>,
    /// Whether the dev `/auth/login` stand-in is enabled (curl / start.sh test).
    pub dev_auth: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info,relay=debug".into()))
        .init();

    // Install the ring-backed rustls crypto provider (process-wide, required by
    // rustls 0.23 before any TLS config is built).
    let _ = rustls::crypto::ring::default_provider().install_default();

    let args = Args::parse();

    // Build the chosen store backend (Postgres connects + runs migrations here).
    tracing::info!(backend = ?args.store, "initializing store backend");
    let stores = store::build_stores(args.store, args.database_url.as_deref()).await?;

    // Seed a few dev claim codes (base + numbered) so multi-instance bulk/fan-out
    // demos work without an operator UI.
    stores.registry.seed_claim(&args.dev_claim, "Dev Home Assistant").await;
    for n in 2..=4 {
        stores
            .registry
            .seed_claim(&format!("{}-{}", args.dev_claim, n), &format!("Dev HA {n}"))
            .await;
    }
    tracing::info!(claim = %args.dev_claim, "seeded dev claim codes (base + -2..-4)");

    // Load or generate the persisted CA (SECURITY-TODO #5).
    let ca = Arc::new(DevCa::load_or_generate(&args.ca_dir)?);

    // Build the presence router (SECURITY-TODO #15): Redis-backed when a URL is
    // configured AND the feature is on, else a single-node local no-op.
    let node = routing::NodeId::generate();
    tracing::info!(node = %node.0, "relay node id");
    let router: Arc<dyn routing::PresenceRouter> = build_router(&node, args.redis_url.as_deref())?;

    // Build OIDC config via discovery when an issuer is configured (#13). A
    // discovery failure is non-fatal: log it and fall back to dev-auth so the
    // relay still comes up (common when Dex is still starting).
    let oidc = if let Some(issuer) = args.oidc_issuer.as_deref() {
        match oidc::OidcConfig::discover(issuer, args.oidc_discovery_base.as_deref(), &args.oidc_client_id, &args.oidc_client_secret, &args.oidc_redirect_uri).await {
            Ok(cfg) => {
                tracing::info!(%issuer, "OIDC discovery ok — real auth-code+PKCE flow enabled");
                Some(Arc::new(cfg))
            }
            Err(e) => {
                tracing::warn!(%issuer, error = %e, "OIDC discovery failed — falling back to dev-auth");
                None
            }
        }
    } else {
        tracing::info!("no OIDC issuer configured — dev-auth only");
        None
    };

    let state = AppState {
        registry: stores.registry,
        hub: Arc::new(Hub::new()),
        ca: ca.clone(),
        audit: stores.audit,
        queue: stores.queue,
        templater: stores.templater,
        collector: stores.collector,
        proxy_authz: stores.proxy_authz,
        sessions: Arc::new(sessions::SessionStore::new()),
        router,
        oidc,
        auth_flights: Arc::new(oidc::AuthFlights::new()),
        dev_auth: args.dev_auth,
    };

    // Build the mTLS server config once (CA-signed server cert + client-cert
    // verification rooted at the CA). Agent-facing endpoints run on this.
    let tls = transport::server_config(&ca)?;

    // --- operator-facing router (stand-in for control plane + frontend) ---
    let op_app = Router::new()
        .route("/instances", get(list_instances))
        .route("/instances/:id/states", get(op_states))
        .route("/instances/:id/notifications", get(op_notifications))
        .route("/instances/:id/services", get(op_services))
        .route("/instances/:id/devices", get(op_devices))
        .route("/instances/:id/updates/pending", get(op_updates_pending))
        .route("/instances/:id/dashboards", get(op_dashboards))
        .route("/instances/:id/dashboards/:dash", get(op_dashboard_get))
        // --- Phase 1: writes (queued when offline), reads, audit ---
        .route("/instances/:id/dashboards/:dash/save", post(op_dashboard_save))
        .route("/instances/:id/automations", get(op_automation_list))
        .route("/instances/:id/automations/:aid", get(op_automation_get))
        .route("/instances/:id/automations/:aid/save", post(op_automation_save))
        .route("/instances/:id/config/check", get(op_config_check))
        .route("/instances/:id/health", get(op_health))
        .route("/instances/:id/logs", get(op_logs))
        .route("/instances/:id/restart", post(op_restart))
        .route("/instances/:id/audit", get(op_audit))
        // --- Phase 2: Supervisor-gated ops + user management ---
        .route("/instances/:id/users", get(op_user_list).post(op_user_create))
        .route("/instances/:id/users/:uid", axum::routing::delete(op_user_delete))
        .route("/instances/:id/backups", get(op_backup_list).post(op_backup_create))
        .route("/instances/:id/backups/:slug/download", get(op_backup_download))
        .route("/instances/:id/backups/:slug/restore", post(op_backup_restore))
        .route("/instances/:id/updates", get(op_update_check))
        .route("/instances/:id/updates/apply", post(op_update_apply))
        // --- Phase 3: templates, bulk push + reconcile, central logs ---
        .route("/templates", get(op_template_list).post(op_template_create))
        .route("/templates/:tid", get(op_template_get))
        .route("/templates/:tid/versions", post(op_template_add_version))
        .route("/templates/:tid/push", post(op_template_push))
        .route("/templates/:tid/jobs", get(op_template_jobs))
        .route("/logs/ingest/:id", post(op_logs_ingest))
        .route("/logs/search", get(op_logs_search))
        // --- Phase 4: identity-aware reverse proxy (FR-7) ---
        .route("/auth/login", post(op_auth_login))
        // --- Real OIDC auth-code + PKCE (SECURITY-TODO #13) ---
        .route("/auth/start", get(oidc::auth_start))
        .route("/auth/callback", get(oidc::auth_callback))
        .route("/auth/me", get(oidc::auth_me))
        .route("/auth/logout", post(oidc::auth_logout))
        .route("/grants", post(op_grant_create))
        .route("/instances/:id/proxy/open", post(op_proxy_open))
        // --- Phase 5: critical-path hardening (self-update, rotation) ---
        .route("/instances/:id/agent/update", post(op_agent_update))
        .route("/instances/:id/rotate/cert", post(op_rotate_cert))
        .route("/instances/:id/revoke", post(op_revoke))
        .route("/claims/:code/revoke", post(op_claim_revoke))
        .route("/instances/:id/owner", get(op_owner))
        // Dev CORS for the Lit/NWC frontend. It now sends the session COOKIE
        // (credentials: 'include'), so we cannot use `*` origin — browsers block
        // credentialed requests to a wildcard origin. Mirror the request origin
        // and allow credentials. Loopback-only control plane; a real deployment
        // serves the SPA same-origin behind the proxy and drops this entirely.
        .layer(
            tower_http::cors::CorsLayer::new()
                .allow_origin(tower_http::cors::AllowOrigin::mirror_request())
                .allow_methods([
                    axum::http::Method::GET,
                    axum::http::Method::POST,
                    axum::http::Method::DELETE,
                    axum::http::Method::OPTIONS,
                ])
                .allow_headers([axum::http::header::CONTENT_TYPE, axum::http::header::AUTHORIZATION])
                .allow_credentials(true),
        )
        .with_state(state.clone());

    // Serve the built SPA same-origin when a frontend dir is configured. This is
    // what lets the httpOnly session cookie set by the OIDC callback reach the
    // API (a split-port dev server cannot). `fallback_service` catches any path
    // not matched by an API route above.
    let op_app = if let Some(dir) = args.frontend_dir.as_ref() {
        if dir.is_dir() {
            tracing::info!(dir = %dir.display(), "serving SPA same-origin on the operator port");
            let serve = tower_http::services::ServeDir::new(dir)
                .append_index_html_on_directories(true);
            op_app.fallback_service(serve)
        } else {
            tracing::warn!(dir = %dir.display(), "--frontend-dir is not a directory; not serving SPA");
            op_app
        }
    } else {
        op_app
    };

    let agent_bind = args.agent_bind.clone();
    let op_bind = args.op_bind.clone();

    let agent_listener = tokio::net::TcpListener::bind(&agent_bind).await?;
    let op_listener = tokio::net::TcpListener::bind(&op_bind).await?;
    tracing::info!(%agent_bind, "agent-facing (enroll + tunnel) listening over mTLS (WSS)");
    tracing::info!(%op_bind, "operator HTTP listening");

    // Agent-facing side is served over mTLS by the transport module (not axum),
    // so it can surface the verified client-cert fingerprint to the handlers.
    let agent_srv = transport::serve(agent_listener, tls, state.clone());
    let op_srv = axum::serve(op_listener, op_app);

    tokio::select! {
        _ = agent_srv => tracing::info!("agent-facing listener ended"),
        r = op_srv => r?,
        _ = tokio::signal::ctrl_c() => tracing::info!("shutting down"),
    }
    Ok(())
}

// --------------------- operator HTTP (control-plane stand-in) ---------------

async fn list_instances(_auth: rbac::ViewerAuth, State(st): State<AppState>) -> impl IntoResponse {
    let out: Vec<_> = st
        .registry
        .list()
        .await
        .into_iter()
        .map(|i| {
            serde_json::json!({
                "instance_id": i.instance_id,
                "display_name": i.display_name,
                "install_type": i.install_type,
                "ha_version": i.ha_version,
                "agent_version": i.agent_version,
                "online": i.is_online(),
                "capabilities": i.capabilities,
            })
        })
        .collect();
    Json(serde_json::json!({ "instances": out }))
}

async fn op_states(_auth: rbac::ViewerAuth, State(st): State<AppState>, Path(id): Path<Uuid>) -> impl IntoResponse {
    read_op(&st, id, hafm_proto::op::STATES_GET, serde_json::json!({})).await
}

async fn op_notifications(_auth: rbac::ViewerAuth, State(st): State<AppState>, Path(id): Path<Uuid>) -> impl IntoResponse {
    read_op(&st, id, hafm_proto::op::NOTIFICATION_LIST, serde_json::json!({})).await
}

async fn op_services(_auth: rbac::ViewerAuth, State(st): State<AppState>, Path(id): Path<Uuid>) -> impl IntoResponse {
    read_op(&st, id, hafm_proto::op::SERVICE_LIST, serde_json::json!({})).await
}

async fn op_devices(_auth: rbac::ViewerAuth, State(st): State<AppState>, Path(id): Path<Uuid>) -> impl IntoResponse {
    read_op(&st, id, hafm_proto::op::DEVICE_LIST, serde_json::json!({})).await
}

async fn op_updates_pending(_auth: rbac::ViewerAuth, State(st): State<AppState>, Path(id): Path<Uuid>) -> impl IntoResponse {
    read_op(&st, id, hafm_proto::op::UPDATE_LIST, serde_json::json!({})).await
}

async fn op_dashboards(State(st): State<AppState>, Path(id): Path<Uuid>) -> impl IntoResponse {
    read_op(&st, id, hafm_proto::op::DASHBOARD_LIST, serde_json::json!({})).await
}

async fn op_dashboard_get(
    State(st): State<AppState>,
    Path((id, dash)): Path<(Uuid, String)>,
) -> impl IntoResponse {
    read_op(&st, id, hafm_proto::op::DASHBOARD_GET, serde_json::json!({ "dashboard_id": dash })).await
}

async fn op_automation_list(State(st): State<AppState>, Path(id): Path<Uuid>) -> impl IntoResponse {
    read_op(&st, id, hafm_proto::op::AUTOMATION_LIST, serde_json::json!({})).await
}

async fn op_automation_get(
    State(st): State<AppState>,
    Path((id, aid)): Path<(Uuid, String)>,
) -> impl IntoResponse {
    read_op(&st, id, hafm_proto::op::AUTOMATION_GET, serde_json::json!({ "automation_id": aid })).await
}

async fn op_config_check(State(st): State<AppState>, Path(id): Path<Uuid>) -> impl IntoResponse {
    read_op(&st, id, hafm_proto::op::CONFIG_CHECK, serde_json::json!({})).await
}

async fn op_health(State(st): State<AppState>, Path(id): Path<Uuid>) -> impl IntoResponse {
    read_op(&st, id, hafm_proto::op::HEALTH_GET, serde_json::json!({})).await
}

async fn op_logs(_auth: rbac::ViewerAuth, State(st): State<AppState>, Path(id): Path<Uuid>) -> impl IntoResponse {
    read_op(&st, id, hafm_proto::op::LOG_STREAM, serde_json::json!({})).await
}

// --- writes: delivered now if online, else queued (NFR-OFF-2) ---

async fn op_dashboard_save(
    _auth: rbac::OperatorAuth,
    State(st): State<AppState>,
    Path((id, dash)): Path<(Uuid, String)>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let args = serde_json::json!({ "dashboard_id": dash, "config": body });
    write_op(&st, id, hafm_proto::op::DASHBOARD_SAVE, args).await
}

async fn op_automation_save(
    _auth: rbac::OperatorAuth,
    State(st): State<AppState>,
    Path((id, aid)): Path<(Uuid, String)>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let args = serde_json::json!({ "automation_id": aid, "config": body });
    write_op(&st, id, hafm_proto::op::AUTOMATION_SAVE, args).await
}

async fn op_restart(
    rbac::AdminAuth(caller): rbac::AdminAuth,
    State(st): State<AppState>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    // Destructive (`05 §6`): requires the Admin role (enforced by the extractor)
    // + step-up auth in a real control plane. Phase 1 records the intent.
    tracing::info!(principal = %caller.principal, %id, "admin restart");
    write_op(&st, id, hafm_proto::op::CORE_RESTART, serde_json::json!({})).await
}

async fn op_audit(
    _auth: rbac::ViewerAuth,
    State(st): State<AppState>,
    Path(id): Path<Uuid>,
    Query(q): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let limit = q.get("limit").and_then(|s| s.parse().ok()).unwrap_or(50);
    let rows = st.audit.query(Some(id), limit).await;
    Json(serde_json::json!({ "audit": rows }))
}

// --- Phase 3 handlers: templater + push engine + reconcile (03 §7, FR-4/4.1/4.2) ---

#[derive(serde::Deserialize)]
struct CreateTemplate {
    kind: TemplateKind,
    name: String,
    body: serde_json::Value,
}

async fn op_template_create(
    _auth: rbac::OperatorAuth,
    State(st): State<AppState>,
    Json(req): Json<CreateTemplate>,
) -> impl IntoResponse {
    let id = st.templater.create(req.kind, &req.name, req.body).await;
    Json(serde_json::json!({ "template_id": id }))
}

async fn op_template_list(State(st): State<AppState>) -> impl IntoResponse {
    let templates = st.templater.list().await;
    Json(serde_json::json!({ "templates": templates }))
}

async fn op_template_get(State(st): State<AppState>, Path(tid): Path<Uuid>) -> impl IntoResponse {
    match st.templater.get(tid).await {
        Some(t) => Json(serde_json::json!({ "template": t })).into_response(),
        None => not_found(),
    }
}

async fn op_template_add_version(
    State(st): State<AppState>,
    Path(tid): Path<Uuid>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    match st.templater.add_version(tid, body).await {
        Some(v) => Json(serde_json::json!({ "version": v })).into_response(),
        None => not_found(),
    }
}

async fn op_template_jobs(State(st): State<AppState>, Path(tid): Path<Uuid>) -> impl IntoResponse {
    let jobs = st.templater.jobs_for(tid).await;
    Json(serde_json::json!({ "jobs": jobs }))
}

/// Target selector for a bulk push. `instances` is explicit; `all=true` fans out
/// to the whole fleet (`FR-4` bulk).
#[derive(serde::Deserialize)]
struct PushRequest {
    #[serde(default)]
    instances: Vec<Uuid>,
    #[serde(default)]
    all: bool,
}

/// **Bulk push + reconcile** (`03 §7`, FR-4/4.1/4.2). For each target instance:
/// push the latest version via the kind's save op, then read the applied state
/// back and compute drift. Idempotent per `(version, instance)`.
async fn op_template_push(
    _auth: rbac::OperatorAuth,
    State(st): State<AppState>,
    Path(tid): Path<Uuid>,
    Json(req): Json<PushRequest>,
) -> axum::response::Response {
    let Some((version, body, kind, save_op)) = st.templater.latest(tid).await else {
        return not_found();
    };

    let targets: Vec<Uuid> = if req.all {
        st.registry.list().await.into_iter().map(|i| i.instance_id).collect()
    } else {
        req.instances.clone()
    };

    let mut results = Vec::new();
    for id in targets {
        if st.registry.get(id).await.is_none() {
            results.push(serde_json::json!({"instance_id": id, "state": "failed", "reason": "unknown instance"}));
            continue;
        }
        let (save_args, read_op_name, read_args) = match kind {
            TemplateKind::Automation => (
                serde_json::json!({"automation_id": "auto_1", "config": body}),
                hafm_proto::op::AUTOMATION_GET,
                serde_json::json!({"automation_id": "auto_1"}),
            ),
            TemplateKind::Dashboard => (
                serde_json::json!({"dashboard_id": "lovelace", "config": body}),
                hafm_proto::op::DASHBOARD_GET,
                serde_json::json!({"dashboard_id": "lovelace"}),
            ),
        };

        let pushed = st.hub.clone().call_via(&st, id, save_op, save_args.clone()).await;
        let state = match pushed {
            Ok(resp) if resp.ok => {
                // reconcile: read back; a successful read after a successful save
                // marks reconciled (a real engine deep-compares vs `body` with an
                // expected-version guard, `03 §7`).
                match st.hub.clone().call_via(&st, id, read_op_name, read_args).await {
                    Ok(rb) if rb.ok => JobState::Reconciled,
                    _ => JobState::Drift,
                }
            }
            _ => JobState::Failed,
        };

        let job = st.templater.record_job(tid, version, id, state, serde_json::json!({"op": save_op})).await;
        st.audit.record(
            Some("operator@dev".into()),
            Some(id),
            "template.push",
            serde_json::json!({"template_id": tid, "version": version}),
            if matches!(state, JobState::Reconciled) { "ok" } else { "error" },
            serde_json::json!({"state": format!("{state:?}")}),
        ).await;
        results.push(serde_json::json!({"instance_id": id, "state": format!("{state:?}").to_lowercase(), "job_id": job}));
    }

    Json(serde_json::json!({ "template_id": tid, "version": version, "pushed": results })).into_response()
}

// --- Phase 3 handlers: central log collection (FR-4.3) ---

async fn op_logs_ingest(State(st): State<AppState>, Path(id): Path<Uuid>) -> axum::response::Response {
    match st.hub.clone().call_via(&st, id, hafm_proto::op::LOG_STREAM, serde_json::json!({})).await {
        Ok(resp) if resp.ok => {
            let lines: Vec<String> = resp
                .result
                .as_ref()
                .and_then(|r| r.get("lines"))
                .and_then(|l| l.as_array())
                .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                .unwrap_or_default();
            let n = st.collector.ingest_lines(id, &lines).await;
            Json(serde_json::json!({ "ingested": n })).into_response()
        }
        Ok(_) => (StatusCode::BAD_GATEWAY, Json(serde_json::json!({"error": "ha_error"}))).into_response(),
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"error": e.to_string()}))).into_response(),
    }
}

async fn op_logs_search(
    State(st): State<AppState>,
    Query(q): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let instance = q.get("instance").and_then(|s| Uuid::parse_str(s).ok());
    let contains = q.get("q").map(|s| s.as_str());
    let limit = q.get("limit").and_then(|s| s.parse().ok()).unwrap_or(50);
    let events = st.collector.query(instance, contains, limit).await;
    Json(serde_json::json!({ "events": events }))
}

// --- Phase 4 handlers: identity-aware reverse proxy (FR-7, 05 §3) ---

#[derive(serde::Deserialize)]
struct GrantReq {
    principal: String,
    instance_id: Uuid,
    #[serde(default)]
    scope: serde_json::Value,
}

/// Operator admin action: grant a principal proxy access to an instance.
async fn op_grant_create(_auth: rbac::AdminAuth, State(st): State<AppState>, Json(req): Json<GrantReq>) -> impl IntoResponse {
    let scope = if req.scope.is_null() { serde_json::json!({"proxy": true}) } else { req.scope };
    st.proxy_authz.grant(&req.principal, req.instance_id, scope).await;
    st.audit.record(Some(req.principal.clone()), Some(req.instance_id), "proxy.grant", serde_json::json!({}), "ok", serde_json::json!({})).await;
    Json(serde_json::json!({ "granted": true }))
}

#[derive(serde::Deserialize)]
struct LoginReq {
    /// The operator principal (OIDC sub). Dev build trusts it directly; a real
    /// deployment populates the session from the OIDC authorization-code
    /// callback instead of this field (SECURITY-TODO #13).
    sub: String,
}

/// Operator login (dev OIDC stand-in): mint a server-side session, return the
/// bearer token. Production replaces this with the OIDC callback that verifies
/// the IdP's id_token and creates the same session.
async fn op_auth_login(State(st): State<AppState>, Json(req): Json<LoginReq>) -> impl IntoResponse {
    if !st.dev_auth {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error": "dev-auth disabled; use OIDC /auth/start"}))).into_response();
    }
    let token = st.sessions.create(&req.sub);
    st.audit.record(Some(req.sub.clone()), None, "auth.login", serde_json::json!({}), "ok", serde_json::json!({})).await;
    Json(serde_json::json!({ "session_token": token, "sub": req.sub })).into_response()
}

#[derive(serde::Deserialize)]
struct ProxyOpenReq {
    #[serde(default)]
    path: Option<String>,
}

/// Extract the operator principal from the `Authorization: Bearer <session>`
/// header, resolved against the verified session store (SECURITY-TODO #13).
fn principal_from_session(st: &AppState, headers: &axum::http::HeaderMap) -> Option<String> {
    let auth = headers.get(axum::http::header::AUTHORIZATION)?.to_str().ok()?;
    let token = auth.strip_prefix("Bearer ").or_else(|| auth.strip_prefix("bearer "))?;
    st.sessions.principal(token)
}

/// The full identity-aware proxy open (`05 §3`, `03 §6`): the principal comes
/// from a VERIFIED operator session (not the request body, #13); authorize the
/// principal→instance grant in the cloud, mint a short-TTL single-consume token,
/// consume it, then issue `proxy.open` to the agent. Default deny.
async fn op_proxy_open(
    State(st): State<AppState>,
    Path(id): Path<Uuid>,
    headers: axum::http::HeaderMap,
    Json(req): Json<ProxyOpenReq>,
) -> axum::response::Response {
    // Principal is derived from the session, never asserted by the client (#13).
    let Some(principal) = principal_from_session(&st, &headers) else {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "no valid operator session; POST /auth/login first"}))).into_response();
    };
    if st.registry.get(id).await.is_none() {
        return not_found();
    }
    // 1. authorize + mint (cloud-side; NFR-SEC-4).
    let token = match st.proxy_authz.mint(&principal, id).await {
        Ok(t) => t,
        Err(e) => {
            st.audit.record(Some(principal.clone()), Some(id), "proxy.open", serde_json::json!({}), "error", serde_json::json!({"authz": format!("{e:?}")})).await;
            return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error": "denied", "detail": format!("{e:?}")}))).into_response();
        }
    };
    // 2. consume the token (single-use) — what the agent-open path checks.
    if let Err(e) = st.proxy_authz.consume(&token.token, id).await {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error": "token", "detail": format!("{e:?}")}))).into_response();
    }
    // 3. issue proxy.open to the agent over the tunnel.
    let path = req.path.unwrap_or_else(|| "/".to_string());
    match st.hub.clone().call_via(&st, id, hafm_proto::op::PROXY_OPEN, serde_json::json!({"path": path, "session_token": token.token})).await {
        Ok(resp) => {
            st.audit.record(Some(principal.clone()), Some(id), "proxy.open", serde_json::json!({"path": path}), if resp.ok {"ok"} else {"error"}, serde_json::json!({"scope": token.scope})).await;
            Json(serde_json::json!({ "opened": resp.ok, "scope": token.scope, "response": resp })).into_response()
        }
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"error": e.to_string()}))).into_response(),
    }
}

// --- Phase 5 handlers: critical-path hardening (05 §5) ---

#[derive(serde::Deserialize)]
struct AgentUpdateReq {
    version: String,
    /// Release signer id (verified against the agent's pinned key).
    #[serde(default)]
    sig: Option<String>,
    /// Simulated post-flip health result for the demo (`true` = passes gate).
    #[serde(default = "default_true")]
    health_ok: bool,
}
fn default_true() -> bool { true }

/// Staged self-update push (`05 §5.2`). The relay issues `agent.update`; the
/// agent runs the A/B-slot + health-gate + watchdog state machine and returns
/// the outcome. A `rolled_back` outcome is where a real control plane HALTS the
/// canary rollout fleet-wide (recorded in the audit log here).
async fn op_agent_update(
    _auth: rbac::OperatorAuth,
    State(st): State<AppState>,
    Path(id): Path<Uuid>,
    Json(req): Json<AgentUpdateReq>,
) -> axum::response::Response {
    if st.registry.get(id).await.is_none() {
        return not_found();
    }
    let sig = req.sig.unwrap_or_else(|| "ha-fleet-release-key-v1".to_string());
    let args = serde_json::json!({"version": req.version, "sig": sig, "health_ok": req.health_ok});
    match st.hub.clone().call_via(&st, id, hafm_proto::op::AGENT_UPDATE, args).await {
        Ok(resp) => {
            let outcome = resp.result.as_ref().and_then(|r| r.get("outcome")).cloned().unwrap_or(serde_json::json!(null));
            let rolled_back = outcome.get("outcome").and_then(|o| o.as_str()) == Some("rolled_back");
            st.audit.record(
                Some("operator@dev".into()),
                Some(id),
                "agent.update",
                serde_json::json!({"version": req.version}),
                if resp.ok && !rolled_back { "ok" } else { "error" },
                serde_json::json!({"outcome": outcome, "rollout": if rolled_back {"HALT_canary"} else {"continue"}}),
            ).await;
            Json(serde_json::json!({ "response": resp, "rollout": if rolled_back {"halt"} else {"continue"} })).into_response()
        }
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"error": e.to_string()}))).into_response(),
    }
}

/// Rotate the pinned mTLS cert fingerprint without re-provisioning (`05 §5.1`).
async fn op_rotate_cert(
    _auth: rbac::AdminAuth,
    State(st): State<AppState>,
    Path(id): Path<Uuid>,
    Json(body): Json<serde_json::Value>,
) -> axum::response::Response {
    let new_fp = body.get("new_fp").and_then(|v| v.as_str()).unwrap_or("rotated-fp").to_string();
    if st.registry.rotate_cert_fp(id, new_fp.clone()).await {
        st.audit.record(Some("operator@dev".into()), Some(id), "rotate.cert", serde_json::json!({}), "ok", serde_json::json!({"new_fp": new_fp})).await;
        Json(serde_json::json!({ "rotated": true, "cert_fp": new_fp })).into_response()
    } else {
        not_found()
    }
}

/// Mark an instance compromised: revoke its cert at the relay (`05 §5.1`). The
/// instance must re-enroll with a fresh claim code to come back.
async fn op_revoke(_auth: rbac::AdminAuth, State(st): State<AppState>, Path(id): Path<Uuid>) -> axum::response::Response {
    if st.registry.set_enroll_state(id, EnrollState::Revoked).await {
        st.registry.unbind_tunnel(id);
        st.audit.record(Some("operator@dev".into()), Some(id), "revoke", serde_json::json!({}), "ok", serde_json::json!({"enroll_state": "revoked"})).await;
        Json(serde_json::json!({ "revoked": true })).into_response()
    } else {
        not_found()
    }
}

/// Revoke an unspent claim code before it is used (`05 §2`, SECURITY-TODO #9) —
/// e.g. if the code leaked. A revoked code's enrollment is refused.
async fn op_claim_revoke(
    _auth: rbac::AdminAuth,
    State(st): State<AppState>,
    Path(code): Path<String>,
) -> axum::response::Response {
    if st.registry.revoke_claim(&code).await {
        st.audit.record(Some("operator@dev".into()), None, "claim.revoke", serde_json::json!({"code": code}), "ok", serde_json::json!({})).await;
        Json(serde_json::json!({ "revoked": true })).into_response()
    } else {
        (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "unknown claim code"}))).into_response()
    }
}

/// Map an op to the capability it requires (`03 §3`). Returns `None` for ops
/// that need no specific capability (always-available core reads).
fn required_capability(op: &str) -> Option<hafm_proto::Capability> {
    use hafm_proto::{op as o, Capability as C};
    Some(match op {
        o::BACKUP_CREATE | o::BACKUP_LIST | o::BACKUP_DOWNLOAD | o::BACKUP_RESTORE => C::SupervisorBackup,
        o::UPDATE_CHECK | o::UPDATE_APPLY => C::SupervisorUpdate,
        o::USER_LIST | o::USER_CREATE | o::USER_UPDATE | o::USER_DELETE => C::CoreUsers,
        _ => return None,
    })
}

/// Enforce capability gating (`FR-8`): if the op needs a capability the instance
/// never advertised, refuse with `capability_missing` and audit it — the op
/// never reaches the agent.
async fn capability_gate(st: &AppState, id: Uuid, op: &str) -> Option<axum::response::Response> {
    let needed = required_capability(op)?;
    let inst = st.registry.get(id).await?;
    if inst.capabilities.contains(&needed) {
        return None;
    }
    st.audit.record(
        Some("operator@dev".into()),
        Some(id),
        op,
        serde_json::json!({}),
        "error",
        serde_json::json!({"error": "capability_missing", "needed": needed.as_str()}),
    ).await;
    Some(
        (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": "capability_missing",
                "needed": needed.as_str(),
                "note": "instance did not advertise this capability (FR-8)"
            })),
        )
            .into_response(),
    )
}

// --- Phase 2 handlers: user management (Core WS) ---

async fn op_user_list(State(st): State<AppState>, Path(id): Path<Uuid>) -> axum::response::Response {
    if let Some(r) = capability_gate(&st, id, hafm_proto::op::USER_LIST).await { return r; }
    read_op(&st, id, hafm_proto::op::USER_LIST, serde_json::json!({})).await
}

async fn op_user_create(
    _auth: rbac::OperatorAuth,
    State(st): State<AppState>,
    Path(id): Path<Uuid>,
    Json(body): Json<serde_json::Value>,
) -> axum::response::Response {
    if let Some(r) = capability_gate(&st, id, hafm_proto::op::USER_CREATE).await { return r; }
    write_op(&st, id, hafm_proto::op::USER_CREATE, body).await
}

async fn op_user_delete(
    _auth: rbac::AdminAuth,
    State(st): State<AppState>,
    Path((id, uid)): Path<(Uuid, String)>,
) -> axum::response::Response {
    if let Some(r) = capability_gate(&st, id, hafm_proto::op::USER_DELETE).await { return r; }
    write_op(&st, id, hafm_proto::op::USER_DELETE, serde_json::json!({ "user_id": uid })).await
}

// --- Phase 2 handlers: Supervisor-gated backups + updates ---

async fn op_backup_list(State(st): State<AppState>, Path(id): Path<Uuid>) -> axum::response::Response {
    if let Some(r) = capability_gate(&st, id, hafm_proto::op::BACKUP_LIST).await { return r; }
    read_op(&st, id, hafm_proto::op::BACKUP_LIST, serde_json::json!({})).await
}

async fn op_backup_create(
    _auth: rbac::OperatorAuth,
    State(st): State<AppState>,
    Path(id): Path<Uuid>,
    Json(body): Json<serde_json::Value>,
) -> axum::response::Response {
    if let Some(r) = capability_gate(&st, id, hafm_proto::op::BACKUP_CREATE).await { return r; }
    write_op(&st, id, hafm_proto::op::BACKUP_CREATE, body).await
}

async fn op_backup_download(
    State(st): State<AppState>,
    Path((id, slug)): Path<(Uuid, String)>,
) -> axum::response::Response {
    if let Some(r) = capability_gate(&st, id, hafm_proto::op::BACKUP_DOWNLOAD).await { return r; }
    read_op(&st, id, hafm_proto::op::BACKUP_DOWNLOAD, serde_json::json!({ "slug": slug })).await
}

async fn op_backup_restore(
    _auth: rbac::AdminAuth,
    State(st): State<AppState>,
    Path((id, slug)): Path<(Uuid, String)>,
) -> axum::response::Response {
    if let Some(r) = capability_gate(&st, id, hafm_proto::op::BACKUP_RESTORE).await { return r; }
    // Destructive (`05 §6`): Admin role (extractor) + step-up in a real plane.
    write_op(&st, id, hafm_proto::op::BACKUP_RESTORE, serde_json::json!({ "slug": slug })).await
}

async fn op_update_check(State(st): State<AppState>, Path(id): Path<Uuid>) -> axum::response::Response {
    if let Some(r) = capability_gate(&st, id, hafm_proto::op::UPDATE_CHECK).await { return r; }
    read_op(&st, id, hafm_proto::op::UPDATE_CHECK, serde_json::json!({})).await
}

async fn op_update_apply(
    _auth: rbac::OperatorAuth,
    State(st): State<AppState>,
    Path(id): Path<Uuid>,
    Json(body): Json<serde_json::Value>,
) -> axum::response::Response {
    if let Some(r) = capability_gate(&st, id, hafm_proto::op::UPDATE_APPLY).await { return r; }
    write_op(&st, id, hafm_proto::op::UPDATE_APPLY, body).await
}

/// A READ: fail fast with `instance_offline` when there is no live tunnel
/// (`NFR-OFF-3`); never queued. Every call is audited (`NFR-SEC-5`).
async fn read_op(
    st: &AppState,
    id: Uuid,
    op: &str,
    args: serde_json::Value,
) -> axum::response::Response {
    if st.registry.get(id).await.is_none() {
        return not_found();
    }
    // Phase 1 actor is a placeholder; Phase 4 OIDC fills in the real principal.
    let actor = Some("operator@dev".to_string());
    match st.hub.clone().call_via(st, id, op, args.clone()).await {
        Ok(resp) => {
            st.audit.record(actor, Some(id), op, args, if resp.ok { "ok" } else { "error" }, serde_json::json!({})).await;
            Json(resp).into_response()
        }
        Err(e) => {
            st.audit.record(actor, Some(id), op, args, "error", serde_json::json!({"error": e.to_string()})).await;
            (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({ "error": e.to_string() })))
                .into_response()
        }
    }
}

/// A WRITE: deliver now if the instance is online, else enqueue with an
/// idempotency key for delivery on reconnect (`NFR-OFF-2`). Audited either way.
async fn write_op(
    st: &AppState,
    id: Uuid,
    op: &str,
    args: serde_json::Value,
) -> axum::response::Response {
    let Some(inst) = st.registry.get(id).await else {
        return not_found();
    };
    let actor = Some("operator@dev".to_string());
    let idem = Uuid::new_v4().to_string();

    if inst.is_online() && st.registry.tunnel(id).is_some() {
        match st.hub.clone().call_via(st, id, op, args.clone()).await {
            Ok(resp) => {
                st.audit.record(actor, Some(id), op, args, if resp.ok { "ok" } else { "error" }, serde_json::json!({"delivery": "online"})).await;
                Json(serde_json::json!({ "delivery": "online", "response": resp })).into_response()
            }
            Err(e) => {
                // Delivery failed mid-flight → queue for retry on reconnect.
                let cmd = st.queue.enqueue(id, op, args.clone(), idem).await;
                st.audit.record(actor, Some(id), op, args, "error", serde_json::json!({"delivery": "queued_after_error", "error": e.to_string()})).await;
                Json(serde_json::json!({ "delivery": "queued", "reason": e.to_string(), "cmd_id": cmd }))
                    .into_response()
            }
        }
    } else {
        let cmd = st.queue.enqueue(id, op, args.clone(), idem).await;
        st.audit.record(actor, Some(id), op, args, "ok", serde_json::json!({"delivery": "queued_offline"})).await;
        let depth = st.queue.depth(id).await;
        (
            StatusCode::ACCEPTED,
            Json(serde_json::json!({ "delivery": "queued", "reason": "instance_offline", "cmd_id": cmd, "queue_depth": depth })),
        )
            .into_response()
    }
}

/// Which relay node currently owns an instance's tunnel (SECURITY-TODO #15).
/// Local router → always this node; Redis router → the node holding the socket.
async fn op_owner(State(st): State<AppState>, Path(id): Path<Uuid>) -> impl IntoResponse {
    let owner = st.router.owner(id).await;
    let here = st.router.owned_here(id).await;
    Json(serde_json::json!({ "instance_id": id, "owner_node": owner, "owned_here": here }))
}

fn not_found() -> axum::response::Response {
    (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "unknown instance"}))).into_response()
}

/// Build the presence router: Redis-backed with `--features redis` + a URL,
/// else the single-node local no-op (SECURITY-TODO #15).
fn build_router(
    node: &routing::NodeId,
    #[allow(unused_variables)] redis_url: Option<&str>,
) -> anyhow::Result<Arc<dyn routing::PresenceRouter>> {
    #[cfg(feature = "redis")]
    if let Some(url) = redis_url {
        tracing::info!(%url, "multi-relay presence routing via Redis");
        return Ok(Arc::new(routing::RedisRouter::connect(url, node.clone())?));
    }
    #[cfg(not(feature = "redis"))]
    if redis_url.is_some() {
        anyhow::bail!("--redis-url requires building the relay with --features redis");
    }
    Ok(Arc::new(routing::LocalRouter::new(node.clone())))
}
