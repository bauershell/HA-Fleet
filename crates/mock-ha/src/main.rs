//! `mock-ha` — a stand-in for Home Assistant Core so the Phase 0 walking
//! skeleton runs with no real HA on the network.
//!
//! It exposes just enough of HA's native surface for the Phase 0 read ops
//! (`03 §5`: `states.get`, `dashboard.list`, `dashboard.get`):
//!
//!   REST  GET  /api/                      → {"message":"API running."}
//!   REST  GET  /api/config                → {version, ...}      (capability probe)
//!   REST  GET  /api/states                → [state objects]
//!   WS         /api/websocket             → HA-style auth + lovelace/config
//!
//! Real HA requires a bearer token on these; the mock accepts any token (it is
//! a test harness, see SECURITY-TODO.md). Supervisor is intentionally absent so
//! the agent's capability detection reports a Container-style install by default.

use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use serde_json::json;
use std::net::SocketAddr;

const BIND: &str = "127.0.0.1:8123";
const HA_VERSION: &str = "2026.9.0";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .init();

    let mut app = Router::new()
        .route("/", get(|| async { axum::response::Html("<html><body><h1>Home Assistant (mock UI)</h1></body></html>") }))
        .route("/api/", get(|| async { Json(json!({"message": "API running."})) }))
        .route("/api/config", get(config))
        .route("/api/config/core/check_config", axum::routing::post(config_check))
        .route("/api/states", get(states))
        .route("/api/error_log", get(error_log))
        .route("/api/notifications", get(notifications))
        .route("/api/services", get(services))
        .route("/api/devices", get(devices))
        .route("/api/updates", get(updates_available))
        .route("/auth/provision", axum::routing::post(auth_provision))
        .route("/api/websocket", get(ws_upgrade));

    // Mock Supervisor surface (HAOS/Supervised only). Enabled when MOCK_SUPERVISOR
    // is set, mirroring a real add-on receiving SUPERVISOR_TOKEN (`05 §2.3`).
    if std::env::var("MOCK_SUPERVISOR").is_ok() {
        app = app
            .route("/supervisor/backups", get(sup_backups).post(sup_backup_create))
            .route("/supervisor/backups/:slug/download", get(sup_backup_download))
            .route("/supervisor/backups/:slug/restore", axum::routing::post(sup_backup_restore))
            .route("/supervisor/available_updates", get(sup_updates))
            .route("/supervisor/update", axum::routing::post(sup_update_apply));
        tracing::info!("mock Supervisor surface ENABLED (supervised/haos simulation)");
    }

    let addr: SocketAddr = std::env::var("MOCK_HA_BIND")
        .unwrap_or_else(|_| BIND.to_string())
        .parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "mock-ha listening (Core REST + WS)");
    axum::serve(listener, app).await?;
    Ok(())
}

/// `GET /api/config` — the agent probes this for HA version + install hints
/// (`02 §2.4` capability detection). Version + name are env-configurable
/// (`MOCK_HA_VERSION` / `MOCK_HA_NAME`) so a dev fleet can show heterogeneous
/// instances; both default to the baseline values.
async fn config() -> impl IntoResponse {
    let version = std::env::var("MOCK_HA_VERSION").unwrap_or_else(|_| HA_VERSION.to_string());
    let name = std::env::var("MOCK_HA_NAME").unwrap_or_else(|_| "Mock Home".to_string());
    Json(json!({
        "version": version,
        "location_name": name,
        "components": ["lovelace", "automation", "config", "websocket_api"],
        "state": "RUNNING",
    }))
}

/// `POST /api/config/core/check_config` — HA's config validation endpoint.
async fn config_check() -> impl IntoResponse {
    Json(json!({"result": "valid", "errors": null, "warnings": null}))
}

/// A small deterministic per-instance seed from the configured name, so the four
/// dev instances show different (but stable) inventories.
fn inst_seed() -> u64 {
    let name = std::env::var("MOCK_HA_NAME").unwrap_or_else(|_| "Mock Home".to_string());
    name.bytes().fold(0u64, |a, b| a.wrapping_mul(31).wrapping_add(b as u64))
}

/// `GET /api/notifications` — HA persistent_notification entities (the bell).
async fn notifications() -> impl IntoResponse {
    let s = inst_seed();
    let mut out = vec![
        json!({"notification_id": "backup_failed", "title": "Backup warning",
               "message": "Last automatic backup was 8 days ago.", "severity": "warning",
               "created_at": "2026-10-08T02:14:00Z"}),
        json!({"notification_id": "welcome", "title": "Welcome home",
               "message": "Home Assistant is up to date on docs.", "severity": "info",
               "created_at": "2026-10-01T09:00:00Z"}),
    ];
    // some instances carry an extra security notice
    if s % 2 == 0 {
        out.push(json!({"notification_id": "new_device", "title": "New device discovered",
               "message": "A new Zigbee device joined the network and needs naming.",
               "severity": "info", "created_at": "2026-10-09T18:40:00Z"}));
    }
    if s % 3 == 0 {
        out.push(json!({"notification_id": "cert_expiry", "title": "TLS certificate",
               "message": "Your Let's Encrypt certificate renews in 6 days.",
               "severity": "warning", "created_at": "2026-10-09T07:00:00Z"}));
    }
    Json(json!({ "notifications": out, "count": out.len() }))
}

/// `GET /api/services` — installed integrations + Supervisor add-ons.
async fn services() -> impl IntoResponse {
    let supervised = std::env::var("MOCK_SUPERVISOR").is_ok();
    let mut integrations = vec![
        json!({"domain": "automation", "name": "Automation", "state": "loaded"}),
        json!({"domain": "mqtt", "name": "MQTT", "state": "loaded"}),
        json!({"domain": "zha", "name": "Zigbee Home Automation", "state": "loaded"}),
        json!({"domain": "hue", "name": "Philips Hue", "state": "loaded"}),
        json!({"domain": "spotify", "name": "Spotify", "state": "loaded"}),
    ];
    if inst_seed() % 2 == 0 {
        integrations.push(json!({"domain": "tesla", "name": "Tesla", "state": "setup_retry"}));
    }
    // Supervisor add-ons only exist on supervised installs.
    let addons = if supervised {
        json!([
            {"slug": "core_mosquitto", "name": "Mosquitto broker", "version": "6.5.1", "state": "started"},
            {"slug": "a0d7b954_nodered", "name": "Node-RED", "version": "18.1.0", "state": "started"},
            {"slug": "core_samba", "name": "Samba share", "version": "12.3.2", "state": "stopped"}
        ])
    } else {
        json!([])
    };
    Json(json!({
        "integrations": integrations,
        "addons": addons,
        "install_type": if supervised { "haos" } else { "container" },
    }))
}

/// `GET /api/devices` — a slice of the HA device registry.
async fn devices() -> impl IntoResponse {
    let s = inst_seed();
    let base = vec![
        json!({"id": "dev_lights_lr", "name": "Living Room Lights", "manufacturer": "Philips", "model": "Hue A19", "area": "Living Room", "entities": 3}),
        json!({"id": "dev_thermostat", "name": "Thermostat", "manufacturer": "ecobee", "model": "SmartThermostat", "area": "Hallway", "entities": 5}),
        json!({"id": "dev_front_door", "name": "Front Door Lock", "manufacturer": "Yale", "model": "Assure 2", "area": "Entry", "entities": 2}),
        json!({"id": "dev_tv", "name": "Living Room TV", "manufacturer": "LG", "model": "C2 OLED", "area": "Living Room", "entities": 4}),
    ];
    // vary device count per instance
    let n = 2 + (s % 3) as usize;
    let devices: Vec<_> = base.into_iter().cycle().take(n + 2).collect();
    Json(json!({ "devices": devices, "count": devices.len() }))
}

/// `GET /api/updates` — HA `update.*` entities that have an update pending.
async fn updates_available() -> impl IntoResponse {
    let version = std::env::var("MOCK_HA_VERSION").unwrap_or_else(|_| HA_VERSION.to_string());
    let s = inst_seed();
    let mut out = vec![
        json!({"entity_id": "update.home_assistant_core", "title": "Home Assistant Core",
               "installed_version": version, "latest_version": "2026.10.1", "in_progress": false}),
    ];
    if s % 2 == 0 {
        out.push(json!({"entity_id": "update.mosquitto_broker", "title": "Mosquitto broker add-on",
               "installed_version": "6.5.1", "latest_version": "6.6.0", "in_progress": false}));
    }
    if s % 3 == 0 {
        out.push(json!({"entity_id": "update.node_red", "title": "Node-RED add-on",
               "installed_version": "18.1.0", "latest_version": "19.0.0", "in_progress": false}));
    }
    Json(json!({ "updates": out, "count": out.len() }))
}

/// `POST /auth/provision` — simulates `05 §2.1` self-provisioning: the agent
/// presents the owner credential ONCE, the mock "creates" a dedicated
/// least-privilege `hafm-agent` user and mints its long-lived token, which the
/// agent stores and uses thereafter. The owner credential is never persisted.
/// A real HA does this via the onboarding/auth APIs.
async fn auth_provision(Json(body): Json<serde_json::Value>) -> impl IntoResponse {
    let owner = body.get("owner_token").and_then(|v| v.as_str()).unwrap_or("");
    if owner.is_empty() {
        return (
            axum::http::StatusCode::UNAUTHORIZED,
            Json(json!({"error": "owner_token required for first-run bootstrap"})),
        );
    }
    // Mint a dedicated token (mock: deterministic-ish). Real HA returns a JWT.
    let agent_token = format!("hafm-agent-llt-{}", owner.len());
    (
        axum::http::StatusCode::OK,
        Json(json!({
            "created_user": "hafm-agent",
            "scope": "least-privilege (dedicated account; HA perms are coarse — 05 §2.2)",
            "long_lived_token": agent_token,
            "note": "owner credential used once and discarded; never stored by the agent"
        })),
    )
}

/// `GET /api/error_log` — HA returns plain text; a couple of lines suffice.
async fn error_log() -> impl IntoResponse {
    "2026-10-09 12:00:00 WARNING (MainThread) [homeassistant.components.foo] deprecated\n2026-10-09 12:01:00 ERROR (MainThread) [homeassistant.components.bar] connection refused\n"
}

/// `GET /api/states` — a tiny but realistic snapshot for `states.get`.
async fn states() -> impl IntoResponse {
    Json(json!([
        {
            "entity_id": "sun.sun",
            "state": "above_horizon",
            "attributes": {"friendly_name": "Sun"},
            "last_changed": "2026-10-09T06:00:00+00:00"
        },
        {
            "entity_id": "light.living_room",
            "state": "on",
            "attributes": {"friendly_name": "Living Room", "brightness": 210},
            "last_changed": "2026-10-09T11:12:00+00:00"
        },
        {
            "entity_id": "sensor.temperature",
            "state": "21.4",
            "attributes": {"friendly_name": "Temperature", "unit_of_measurement": "°C"},
            "last_changed": "2026-10-09T12:00:00+00:00"
        }
    ]))
}

async fn ws_upgrade(ws: WebSocketUpgrade) -> impl IntoResponse {
    ws.on_upgrade(ws_session)
}

// -------- mock Supervisor REST (HAOS/Supervised; MOCK_SUPERVISOR) ----------

async fn sup_backups() -> impl IntoResponse {
    Json(json!({"result": "ok", "data": {"backups": [
        {"slug": "abc123", "name": "nightly", "date": "2026-10-09T03:00:00+00:00", "size": 148.2}
    ]}}))
}

async fn sup_backup_create(Json(body): Json<serde_json::Value>) -> impl IntoResponse {
    let name = body.get("name").and_then(|n| n.as_str()).unwrap_or("manual");
    Json(json!({"result": "ok", "data": {"slug": "newslug", "name": name}}))
}

async fn sup_backup_download(axum::extract::Path(slug): axum::extract::Path<String>) -> impl IntoResponse {
    // Real Supervisor streams a tar; the mock returns a tiny byte blob so the
    // orchestrator's GCS-staging path (04 §5) has something to move.
    (
        [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
        format!("MOCK-BACKUP-BLOB:{slug}").into_bytes(),
    )
}

async fn sup_backup_restore(axum::extract::Path(slug): axum::extract::Path<String>) -> impl IntoResponse {
    Json(json!({"result": "ok", "data": {"job_id": format!("restore-{slug}")}}))
}

async fn sup_updates() -> impl IntoResponse {
    Json(json!({"result": "ok", "data": {
        "core": {"version_latest": "2026.10.0", "update_available": true},
        "os": {"version_latest": "13.0", "update_available": false}
    }}))
}

async fn sup_update_apply(Json(body): Json<serde_json::Value>) -> impl IntoResponse {
    let target = body.get("target").and_then(|t| t.as_str()).unwrap_or("core");
    Json(json!({"result": "ok", "data": {"job_id": format!("update-{target}")}}))
}

/// Minimal HA WebSocket API: the real one sends `auth_required`, expects an
/// `auth` message, replies `auth_ok`, then serves commands by `id`+`type`.
/// Phase 0 needs `lovelace/config` (dashboard get) and a dashboard list.
async fn ws_session(mut socket: WebSocket) {
    // HA sends auth_required first.
    if socket
        .send(Message::Text(json!({"type": "auth_required", "ha_version": HA_VERSION}).to_string()))
        .await
        .is_err()
    {
        return;
    }

    while let Some(Ok(msg)) = socket.recv().await {
        let Message::Text(txt) = msg else { continue };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&txt) else { continue };
        let mtype = v.get("type").and_then(|t| t.as_str()).unwrap_or("");
        let id = v.get("id").and_then(|i| i.as_u64()).unwrap_or(0);

        let reply = match mtype {
            // Accept any token — test harness only.
            "auth" => json!({"type": "auth_ok", "ha_version": HA_VERSION}),

            // `dashboard.list` broker reads the lovelace dashboards collection.
            "lovelace/dashboards/list" => json!({
                "id": id, "type": "result", "success": true,
                "result": [
                    {"id": "lovelace", "title": "Overview", "url_path": null},
                    {"id": "lovelace-energy", "title": "Energy", "url_path": "energy"}
                ]
            }),

            // `dashboard.get` → lovelace/config for one dashboard.
            "lovelace/config" => json!({
                "id": id, "type": "result", "success": true,
                "result": {
                    "title": "Overview",
                    "views": [{
                        "title": "Home",
                        "cards": [
                            {"type": "entities", "entities": ["light.living_room", "sensor.temperature"]}
                        ]
                    }]
                }
            }),

            // `dashboard.save` → lovelace/config/save (Phase 1, FR-4.2).
            "lovelace/config/save" => json!({"id": id, "type": "result", "success": true, "result": null}),

            // `automation.list` → config/automation/config list.
            "automation/list" => json!({
                "id": id, "type": "result", "success": true,
                "result": [
                    {"id": "auto_1", "alias": "Sunset lights"},
                    {"id": "auto_2", "alias": "Away mode"}
                ]
            }),
            "automation/get" => json!({
                "id": id, "type": "result", "success": true,
                "result": {"id": "auto_1", "alias": "Sunset lights", "trigger": [], "action": []}
            }),
            "automation/save" => json!({"id": id, "type": "result", "success": true, "result": {"version": 2}}),
            "automation/reload" => json!({"id": id, "type": "result", "success": true, "result": null}),

            // `health.get` → system_health/info.
            "system_health/info" => json!({
                "id": id, "type": "result", "success": true,
                "result": {"homeassistant": {"version": HA_VERSION, "healthy": true}}
            }),

            // user.* → config/auth (Phase 2, FR-2.3/6.5).
            "config/auth/list" => json!({
                "id": id, "type": "result", "success": true,
                "result": [
                    {"id": "owner-uid", "name": "Owner", "is_owner": true, "is_active": true},
                    {"id": "hafm-agent-uid", "name": "hafm-agent", "is_owner": false, "is_active": true}
                ]
            }),
            "config/auth/create" => json!({
                "id": id, "type": "result", "success": true,
                "result": {"id": "new-uid", "name": v.get("name").and_then(|n| n.as_str()).unwrap_or("new")}
            }),
            "config/auth/update" => json!({"id": id, "type": "result", "success": true, "result": null}),
            "config/auth/delete" => json!({"id": id, "type": "result", "success": true, "result": null}),

            other => json!({
                "id": id, "type": "result", "success": false,
                "error": {"code": "unknown_command", "message": format!("mock-ha has no handler for {other}")}
            }),
        };

        if socket.send(Message::Text(reply.to_string())).await.is_err() {
            break;
        }
    }
}
