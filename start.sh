#!/usr/bin/env bash
# ha-fleet — no-brain local dev runner.
#
#   ./start.sh up        build + start the whole stack (pg, redis, mock-ha, relay, agent)
#   ./start.sh down      stop everything (keeps data volumes)
#   ./start.sh reset     stop + delete volumes (fresh DB, fresh CA, re-enroll)
#   ./start.sh logs      follow all logs   (./start.sh logs relay → one service)
#   ./start.sh status    one-line health of every service + the fleet
#   ./start.sh test      run the all-phases smoke test against the running stack
#   ./start.sh frontend  serve the read-only Lit UI on http://127.0.0.1:8090
#   ./start.sh rebuild   rebuild the dev image (after code changes) and restart
#
# Everything binds to 127.0.0.1 only. The operator API is http://127.0.0.1:8080.
set -euo pipefail
cd "$(dirname "$0")"

# Prefer standalone podman-compose (python, talks to podman directly); fall back
# to the `podman compose` plugin only if the standalone one is absent.
if command -v podman-compose >/dev/null 2>&1; then
  COMPOSE="podman-compose"
elif podman compose version >/dev/null 2>&1; then
  COMPOSE="podman compose"
else
  echo "need podman-compose or the podman compose plugin on PATH" >&2; exit 1
fi
FILE="podman-compose.yml"
OP="http://127.0.0.1:8080"

c() { $COMPOSE -f "$FILE" "$@"; }

# Generate the real deploy/dex-config.yaml (git-ignored) from the committed
# template + .env, substituting ${DEX_CLIENT_SECRET} and ${DEX_USER_PASSWORD_HASH}
# literally. Done in start.sh (not via Dex env-expansion) because a bcrypt hash
# contains '$' segments that Dex would otherwise try to expand and corrupt.
gen_dex_config() {
  local tmpl="deploy/dex-config.example.yaml" out="deploy/dex-config.yaml"
  if [ ! -f .env ]; then
    if [ -f .env.example ]; then
      echo "▶ no .env found — creating it from .env.example (dev defaults)"; cp .env.example .env
    else
      echo "✗ missing .env and .env.example — cannot generate Dex config" >&2; exit 1
    fi
  fi
  # shellcheck disable=SC1091
  set -a; . ./.env; set +a
  : "${DEX_CLIENT_SECRET:?set DEX_CLIENT_SECRET in .env}"
  : "${DEX_USER_PASSWORD_HASH:?set DEX_USER_PASSWORD_HASH in .env}"
  # Literal substitution (no eval), so the '$' in the bcrypt hash is left intact.
  sed -e "s|\${DEX_CLIENT_SECRET}|${DEX_CLIENT_SECRET}|g" \
      -e "s|\${DEX_USER_PASSWORD_HASH}|${DEX_USER_PASSWORD_HASH}|g" \
      "$tmpl" > "$out"
  echo "✓ generated $out from $tmpl + .env"
}

# Mint a short-lived dev-auth (Admin) session token for CLI reads, which are now
# session-gated. Echoes the token (empty on failure).
dev_token() {
  curl -s -X POST "$OP/auth/login" -H 'content-type: application/json' -d '{"sub":"cli@dev"}' \
    | python3 -c 'import sys,json;print(json.load(sys.stdin).get("session_token",""))' 2>/dev/null
}

cmd_up() {
  gen_dex_config
  echo "▶ building + starting the stack (first run compiles Rust — a minute or two)…"
  c up -d --build
  echo "▶ waiting for the relay operator API…"
  for i in $(seq 1 60); do
    # The SPA root is unauthenticated; /instances is now session-gated.
    if curl -fsS "$OP/" >/dev/null 2>&1; then
      echo "✓ relay up at $OP"; break
    fi
    sleep 2
    [ "$i" = 60 ] && { echo "✗ relay never came up — ./start.sh logs relay"; exit 1; }
  done
  echo "▶ waiting for the agent to enroll + connect…"
  TOK=$(dev_token)
  for i in $(seq 1 30); do
    online=$(curl -fsS -H "authorization: Bearer $TOK" "$OP/instances" 2>/dev/null | grep -c '"online":true' || true)
    [ "${online:-0}" -ge 1 ] && { echo "✓ agent online"; break; }
    sleep 2
  done
  echo
  cmd_status
  echo
  echo "Next:  ./start.sh test     (all-phases smoke)   ·   ./start.sh frontend   (web UI)"
}

cmd_down()  { echo "▶ stopping (data volumes kept)…"; c down; }
cmd_reset() { echo "▶ stopping + deleting volumes (fresh DB/CA, re-enroll)…"; c down -v; }
cmd_rebuild(){ gen_dex_config; echo "▶ rebuilding image + restarting…"; c up -d --build --force-recreate; cmd_status; }

cmd_logs() {
  if [ $# -gt 0 ]; then c logs -f "$1"; else c logs -f; fi
}

cmd_status() {
  echo "── services ─────────────────────────────"
  c ps 2>/dev/null | tail -n +1 || true
  echo "── fleet ────────────────────────────────"
  TOK=$(dev_token)
  if curl -fsS "$OP/" >/dev/null 2>&1; then
    curl -fsS -H "authorization: Bearer $TOK" "$OP/instances" | python3 -c '
import sys, json
d = json.load(sys.stdin).get("instances", [])
if not d: print("  (no instances enrolled yet)")
for i in d:
    print(f"  {i[\"display_name\"]:<22} {\"online\" if i[\"online\"] else \"offline\":<8} {i[\"install_type\"]:<11} HA {i.get(\"ha_version\") or \"-\"}  caps={len(i.get(\"capabilities\",[]))}")
' 2>/dev/null || echo "  (could not parse /instances)"
  else
    echo "  operator API not reachable at $OP — is the stack up? (./start.sh up)"
  fi
}

# All-phases smoke test against the running stack. No build, no deps beyond
# curl + python3. Each line prints PASS/FAIL; exits non-zero on any failure.
cmd_test() {
  command -v curl >/dev/null || { echo "need curl"; exit 1; }
  # Reads are now session-gated too — mint an ADMIN dev session FIRST, then use
  # its bearer for everything (readiness, IID resolution, reads, and writes).
  ADMIN=$(curl -s -X POST "$OP/auth/login" -H 'content-type: application/json' -d '{"sub":"admin@test"}' | python3 -c 'import sys,json;print(json.load(sys.stdin).get("session_token",""))' 2>/dev/null)
  [ -n "$ADMIN" ] || { echo "could not get a dev-auth session — is the stack up? (./start.sh up)"; exit 1; }
  AUTH="authorization: Bearer $ADMIN"
  curl -fsS -H "$AUTH" "$OP/instances" >/dev/null 2>&1 || { echo "stack not up — run ./start.sh up"; exit 1; }
  IID=$(curl -fsS -H "$AUTH" "$OP/instances" | python3 -c 'import sys,json;x=json.load(sys.stdin)["instances"];print(x[0]["instance_id"] if x else "")')
  [ -n "$IID" ] || { echo "no instance enrolled — ./start.sh reset && ./start.sh up"; exit 1; }
  echo "instance: $IID"
  pass=0; fail=0
  chk() { # name  "test-expr"
    if eval "$2" >/dev/null 2>&1; then printf "  ✓ %s\n" "$1"; pass=$((pass+1));
    else printf "  ✗ %s\n" "$1"; fail=$((fail+1)); fi
  }
  code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
  body() { curl -s "$@"; }

  echo "── all-phases smoke ─────────────────────"
  chk "P0 status: instance online"        "curl -fsS -H \"$AUTH\" $OP/instances | grep -q '\"online\":true'"
  chk "P0 read: states"                   "[ \$(code -H \"$AUTH\" $OP/instances/$IID/states) = 200 ]"
  chk "P1 write: dashboard save online"   "body -X POST $OP/instances/$IID/dashboards/lovelace/save -H \"$AUTH\" -H 'content-type: application/json' -d '{\"t\":1}' | grep -q '\"delivery\":\"online\"'"
  chk "P1 audit log non-empty"            "body -H \"$AUTH\" $OP/instances/$IID/audit | grep -q audit"
  chk "P2 supervisor backups 200 (haos)"  "[ \$(code -H \"$AUTH\" $OP/instances/$IID/backups) = 200 ]"
  chk "P2 user list 200"                  "[ \$(code -H \"$AUTH\" $OP/instances/$IID/users) = 200 ]"
  chk "inventory: notifications"          "body -H \"$AUTH\" $OP/instances/$IID/notifications | grep -q notifications"
  chk "inventory: services + addons"      "body -H \"$AUTH\" $OP/instances/$IID/services | grep -q integrations"
  chk "inventory: devices"                "body -H \"$AUTH\" $OP/instances/$IID/devices | grep -q devices"
  chk "inventory: pending updates"        "body -H \"$AUTH\" $OP/instances/$IID/updates/pending | grep -q updates"
  chk "gate: reads need a session (401)"  "[ \$(code $OP/instances) = 401 ]"
  TID=$(body -X POST $OP/templates -H "$AUTH" -H 'content-type: application/json' -d '{"kind":"dashboard","name":"d","body":{}}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["template_id"])')
  chk "P3 template push reconciled"       "body -X POST $OP/templates/$TID/push -H \"$AUTH\" -H 'content-type: application/json' -d '{\"all\":true}' | grep -q reconciled"
  body -X POST "$OP/logs/ingest/$IID" >/dev/null 2>&1 || true
  chk "P3 fleet log search"               "body '$OP/logs/search?q=connection' | grep -q events"
  # Fresh principal per run so the deny step is deterministic even against a
  # reused volume (a never-seen subject provably has no standing grant).
  PRIN="smoke-$(date +%s)-$$@test"
  SESS=$(body -X POST $OP/auth/login -H 'content-type: application/json' -d "{\"sub\":\"$PRIN\"}" | python3 -c 'import sys,json;print(json.load(sys.stdin)["session_token"])')
  chk "P4 proxy denied w/o grant (403)"   "[ \$(code -X POST $OP/instances/$IID/proxy/open -H \"authorization: Bearer $SESS\" -H 'content-type: application/json' -d '{}') = 403 ]"
  body -X POST "$OP/grants" -H "$AUTH" -H 'content-type: application/json' -d "{\"principal\":\"$PRIN\",\"instance_id\":\"$IID\",\"scope\":{\"proxy\":true}}" >/dev/null
  chk "P4 proxy opened after grant"       "body -X POST $OP/instances/$IID/proxy/open -H \"authorization: Bearer $SESS\" -H 'content-type: application/json' -d '{}' | grep -q '\"opened\":true'"
  # Always exactly one patch newer than whatever slot the (possibly reused)
  # agentstate volume currently holds — clock-independent, so even back-to-back
  # runs within the same second still flip. We read the live running_version via
  # a deliberately-old probe (rejected, but it echoes running_version), then bump
  # its last numeric field.
  CURV=$(body -X POST $OP/instances/$IID/agent/update -H "$AUTH" -H 'content-type: application/json' -d '{"version":"0.0.0","health_ok":true}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["response"]["result"]["running_version"])' 2>/dev/null || echo "0.0.0")
  UPV=$(python3 -c "p='$CURV'.lstrip('vV').split('.');p[-1]=str(int(p[-1])+1) if p[-1].isdigit() else '1';print('.'.join(p))")
  chk "P5 self-update slot flip"          "body -X POST $OP/instances/$IID/agent/update -H \"$AUTH\" -H 'content-type: application/json' -d '{\"version\":\"$UPV\",\"health_ok\":true}' | grep -qi applied"
  chk "#15 presence owner known"          "body $OP/instances/$IID/owner | grep -q owner_node"
  # RBAC enforcement is live: an unauthenticated destructive op is 401, an admin
  # session is allowed. (Dev-auth only mints Admin, so viewer-denied is unit-tested.)
  chk "RBAC: no session → restart 401"    "[ \$(code -X POST $OP/instances/$IID/restart) = 401 ]"
  chk "RBAC: admin → restart 200"         "[ \$(code -X POST $OP/instances/$IID/restart -H \"$AUTH\") = 200 ]"
  echo "─────────────────────────────────────────"
  echo "  $pass passed, $fail failed"
  [ "$fail" = 0 ] && echo "  ALL GREEN ✅" || { echo "  SOME FAILED ❌"; exit 1; }
}

cmd_frontend() {
  echo "▶ the UI is served SAME-ORIGIN by the relay at:"
  echo
  echo "      http://127.0.0.1:8080/"
  echo
  echo "  Open that in your browser. 'Log in with OIDC' → Dex (admin@/operator@/"
  echo "  viewer@ ha-fleet.dev, password 'password') → role-aware actions."
  echo "  (Serving same-origin is what lets the session cookie reach the API.)"
}

case "${1:-}" in
  up)       cmd_up ;;
  down)     cmd_down ;;
  reset)    cmd_reset ;;
  rebuild)  cmd_rebuild ;;
  logs)     shift; cmd_logs "$@" ;;
  status)   cmd_status ;;
  test)     cmd_test ;;
  frontend) cmd_frontend ;;
  *)
    echo "ha-fleet dev runner"
    echo "usage: ./start.sh {up|down|reset|rebuild|logs [svc]|status|test|frontend}"
    exit 2 ;;
esac
