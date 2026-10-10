//! `cargo xtask e2e` — a committed, repeatable end-to-end harness.
//!
//! Replaces the ad-hoc bash walks: builds the workspace binaries, boots
//! mock-ha + relay + agent on loopback, enrolls over mTLS, and asserts an op
//! from every phase (P0 status/read, P1 write+offline-queue, P2 Supervisor
//! gating, P3 template push + log search, P4 proxy deny→grant via an operator
//! session, P5 self-update). Exits non-zero on the first failed assertion.
//!
//! Pure std + a tiny loopback HTTP client (no extra deps), matching the repo's
//! dependency-light style. Run from the repo root: `cargo xtask e2e`.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

fn main() -> anyhow::Result<()> {
    let task = std::env::args().nth(1).unwrap_or_default();
    match task.as_str() {
        "e2e" => e2e(),
        other => {
            eprintln!("unknown task '{other}'. usage: cargo xtask e2e");
            std::process::exit(2);
        }
    }
}

/// A spawned child that is killed on drop (so a panic/early-return cleans up).
struct Proc(Child);
impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn repo_root() -> PathBuf {
    // CARGO_MANIFEST_DIR = <root>/xtask; parent is the repo root.
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
}

fn e2e() -> anyhow::Result<()> {
    let root = repo_root();
    let scratch = root.join("target/xtask-e2e");
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir_all(&scratch)?;

    eprintln!("[xtask] building workspace binaries…");
    run(Command::new("cargo").args(["build", "-p", "relay", "-p", "agent", "-p", "mock-ha"]).current_dir(&root))?;

    let bin = |n: &str| root.join("target/debug").join(n);
    let ca_dir = scratch.join("ca");
    let agent_state = scratch.join("agent-state");

    eprintln!("[xtask] starting mock-ha (supervised) …");
    let _mock = Proc(
        Command::new(bin("mock-ha"))
            .env("MOCK_SUPERVISOR", "1")
            .env("RUST_LOG", "warn")
            .stdout(Stdio::null()).stderr(Stdio::null())
            .spawn()?,
    );
    sleep(1000);

    eprintln!("[xtask] starting relay (WSS/mTLS, in-memory store) …");
    let _relay = Proc(
        Command::new(bin("relay"))
            .env("RELAY_CA_DIR", &ca_dir)
            .env("RUST_LOG", "warn")
            .stdout(Stdio::null()).stderr(Stdio::null())
            .spawn()?,
    );
    wait_port(8080, 50)?;

    eprintln!("[xtask] enrolling agent over mTLS …");
    run(Command::new(bin("agent"))
        .args(["enroll", "--claim-code", "DEV-CLAIM-0001",
               "--relay", "wss://127.0.0.1:8443"])
        .arg("--relay-ca").arg(ca_dir.join("ca-cert.pem"))
        .arg("--state-dir").arg(&agent_state)
        .env("SUPERVISOR_TOKEN", "mock")
        .env("RUST_LOG", "warn"))?;

    eprintln!("[xtask] starting agent (steady-state tunnel) …");
    let _agent = Proc(
        Command::new(bin("agent"))
            .arg("--relay").arg("wss://127.0.0.1:8443")
            .arg("--state-dir").arg(&agent_state)
            .env("SUPERVISOR_TOKEN", "mock")
            .env("RUST_LOG", "warn")
            .stdout(Stdio::null()).stderr(Stdio::null())
            .spawn()?,
    );
    sleep(2500);

    // Auth first — reads are session-gated now. Dev-auth mints an Admin session.
    let login = http_post("127.0.0.1:8080", "/auth/login", "{\"sub\":\"alice@corp\"}", &[])?;
    let session = json_field(&login, "session_token").unwrap_or_default();
    let auth = format!("Authorization: Bearer {session}");

    // --- resolve instance id (authed) ---
    let instances = http_get_auth("127.0.0.1:8080", "/instances", &auth)?;
    let iid = json_first_instance_id(&instances)
        .ok_or_else(|| anyhow::anyhow!("no instance enrolled; body={instances}"))?;
    eprintln!("[xtask] instance_id={iid}");

    // reads must be refused without a session (gate check)
    let unauth_read = http_get("127.0.0.1:8080", "/instances");
    let read_gated = matches!(&unauth_read, Err(e) if e.to_string().contains("401"));

    let mut pass = 0u32;
    let mut check = |name: &str, cond: bool| {
        if cond { pass += 1; eprintln!("  ✓ {name}"); }
        else { eprintln!("  ✗ {name}"); }
        cond
    };

    // P0: status online + a read
    let ok_status = instances.contains("\"online\":true");
    let states = http_get_auth("127.0.0.1:8080", &format!("/instances/{iid}/states"), &auth)?;
    // Inventory reads (notifications / services / devices / updates)
    let notifs = http_get_auth("127.0.0.1:8080", &format!("/instances/{iid}/notifications"), &auth)?;
    let svcs = http_get_auth("127.0.0.1:8080", &format!("/instances/{iid}/services"), &auth)?;
    let devs = http_get_auth("127.0.0.1:8080", &format!("/instances/{iid}/devices"), &auth)?;
    let upds = http_get_auth("127.0.0.1:8080", &format!("/instances/{iid}/updates/pending"), &auth)?;
    // P1: a write (online delivery) + audit
    let save = http_post("127.0.0.1:8080", &format!("/instances/{iid}/dashboards/lovelace/save"), "{\"title\":\"x\"}", &[&auth])?;
    // P2: Supervisor op works on supervised (200 + a backups array)
    let backups = http_get_auth("127.0.0.1:8080", &format!("/instances/{iid}/backups"), &auth)?;
    // P3: template create + push + log search
    let tmpl = http_post("127.0.0.1:8080", "/templates", "{\"kind\":\"dashboard\",\"name\":\"d\",\"body\":{}}", &[&auth])?;
    let tid = json_field(&tmpl, "template_id").unwrap_or_default();
    let push = http_post("127.0.0.1:8080", &format!("/templates/{tid}/push"), "{\"all\":true}", &[&auth])?;
    http_post("127.0.0.1:8080", &format!("/logs/ingest/{iid}"), "", &[])?;
    let search = http_get("127.0.0.1:8080", "/logs/search?q=connection")?;
    // P4: proxy — session → deny without grant → grant → allow (#13)
    let deny = http_post("127.0.0.1:8080", &format!("/instances/{iid}/proxy/open"), "{}", &[&auth]);
    let deny_403 = matches!(&deny, Err(e) if e.to_string().contains("403"));
    http_post("127.0.0.1:8080", "/grants", &format!("{{\"principal\":\"alice@corp\",\"instance_id\":\"{iid}\",\"scope\":{{\"proxy\":true}}}}"), &[&auth])?;
    let open = http_post("127.0.0.1:8080", &format!("/instances/{iid}/proxy/open"), "{}", &[&auth])?;
    // RBAC: an unauthenticated destructive op must be refused (401).
    let no_auth_restart = http_post("127.0.0.1:8080", &format!("/instances/{iid}/restart"), "", &[]);
    let rbac_401 = matches!(&no_auth_restart, Err(e) if e.to_string().contains("401"));
    // P5: self-update (healthy flip)
    let upd = http_post("127.0.0.1:8080", &format!("/instances/{iid}/agent/update"), "{\"version\":\"9.9.9\",\"health_ok\":true}", &[&auth])?;

    eprintln!("[xtask] assertions:");
    let all = [
        check("P0 instance online", ok_status),
        check("P0 states read ok", states.contains("entity_id") || states.contains("sun")),
        check("inventory: notifications", notifs.contains("notifications")),
        check("inventory: services + addons", svcs.contains("integrations")),
        check("inventory: devices", devs.contains("devices")),
        check("inventory: pending updates", upds.contains("updates")),
        check("reads require a session (401 unauth)", read_gated),
        check("P1 dashboard save delivered online", save.contains("\"delivery\":\"online\"")),
        check("P2 supervisor backups 200 (supervised)", backups.contains("backups") || backups.starts_with('[') || backups.contains("slug")),
        check("P3 template push reconciled", push.contains("reconciled")),
        check("P3 fleet log search matched", search.contains("connection") || search.contains("events")),
        check("P4 proxy denied without grant (403)", deny_403),
        check("P4 proxy opened after grant via session", open.contains("\"opened\":true")),
        check("RBAC destructive op denied without session (401)", rbac_401),
        check("P5 self-update applied (slot flip)", upd.contains("applied") || upd.contains("Applied")),
    ];
    let total = all.len() as u32;
    eprintln!("[xtask] {pass}/{total} checks passed");
    if pass == total {
        eprintln!("[xtask] E2E PASSED ✅");
        Ok(())
    } else {
        anyhow::bail!("E2E FAILED: {}/{} checks passed", pass, total)
    }
}

// --------------------------- helpers ---------------------------------------

fn run(cmd: &mut Command) -> anyhow::Result<()> {
    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("command failed: {:?}", cmd);
    }
    Ok(())
}

fn sleep(ms: u64) { std::thread::sleep(Duration::from_millis(ms)); }

fn wait_port(port: u16, tries: u32) -> anyhow::Result<()> {
    for _ in 0..tries {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() { return Ok(()); }
        sleep(100);
    }
    anyhow::bail!("port {port} never came up")
}

/// Minimal loopback HTTP GET → body string; errors carry the status for 4xx/5xx.
fn http_get(authority: &str, path: &str) -> anyhow::Result<String> {
    http_req(authority, "GET", path, "", &[])
}
fn http_get_auth(authority: &str, path: &str, auth: &str) -> anyhow::Result<String> {
    http_req(authority, "GET", path, "", &[auth])
}
fn http_post(authority: &str, path: &str, body: &str, extra_headers: &[&str]) -> anyhow::Result<String> {
    http_req(authority, "POST", path, body, extra_headers)
}

fn http_req(authority: &str, method: &str, path: &str, body: &str, extra: &[&str]) -> anyhow::Result<String> {
    let mut stream = TcpStream::connect(authority)?;
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n"
    );
    for h in extra { req.push_str(h); req.push_str("\r\n"); }
    if method == "POST" {
        req.push_str("Content-Type: application/json\r\n");
        req.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    req.push_str("\r\n");
    req.push_str(body);
    stream.write_all(req.as_bytes())?;
    let mut raw = String::new();
    stream.read_to_string(&mut raw)?;
    let status = raw.lines().next().unwrap_or("");
    let code: u16 = status.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
    let resp_body = raw.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    if !(200..300).contains(&code) {
        anyhow::bail!("HTTP {code} on {method} {path}: {}", resp_body.trim());
    }
    Ok(resp_body)
}

/// Pull the first `"instance_id":"<uuid>"` out of the /instances JSON.
fn json_first_instance_id(body: &str) -> Option<String> {
    json_field(body, "instance_id")
}

/// Extract a `"key":"value"` string field (first occurrence) — tiny, no serde.
fn json_field(body: &str, key: &str) -> Option<String> {
    let pat = format!("\"{key}\":\"");
    let start = body.find(&pat)? + pat.len();
    let rest = &body[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}
