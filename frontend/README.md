# ha-fleet frontend (Lit + Native Web Components)

A fleet **manager** (read + write) built as native custom elements with
[Lit](https://lit.dev) — no build step, Lit loaded from a CDN ESM bundle.

## Elements

- `<fleet-view>` — polls `/instances` every 5s, renders the grid + the
  fleet-wide templates panel.
- `<instance-card>` — one instance tile (online dot, install type, versions,
  capability chips).
- `<instance-detail>` — tabbed manage modal for one instance:
  - **inspect** — read-only `states` + recent `logs`.
  - **manage** — restart HA Core, config check, health, dashboard save
    (shows online-vs-queued delivery).
  - **backups** — list / create / restore (Supervisor-gated).
  - **users** — list / create / delete HA users (capability-gated).
  - **proxy** — grant yourself access, then open the identity-aware proxy
    (default-deny; principal comes from your verified session).
  - **update** — self-update push (A/B slot flip + health gate; uncheck
    "health passes" to see a rollback), cert rotation, revoke.
  - **audit** — the instance's last 20 audit-log entries.
- `<session-bar>` — operator login/logout. Logs in via `POST /auth/login`
  (dev OIDC stand-in) and keeps the bearer token **in memory** for the proxy.
- `<templates-panel>` — list templates, create one, bulk-push to the whole
  fleet with per-instance reconcile results.
- `<result-box>` — every write action shows its HTTP status + JSON response.

Every button maps 1:1 to a real operator endpoint; there is no mock data.

## Run (dev)

Bring the stack up, then serve this dir on loopback:

```sh
./start.sh up                 # pg, redis, mock-ha, relay, agent
./start.sh frontend           # serves http://127.0.0.1:8090 (foreground)
# open http://127.0.0.1:8090/  (defaults to API http://127.0.0.1:8080;
# override with ?api=http://host:port)
```

The relay's operator API enables permissive CORS in dev so the page (on another
port) can fetch it. **To use the proxy tab you must log in** (top-right) — the
proxy derives its principal from a verified session, not a request field.

## Build note

The skeleton loads Lit from a CDN ESM bundle for zero build tooling. A real
deployment bundles Lit with Vite/esbuild and serves the SPA same-origin behind
the identity-aware proxy (dropping the CORS layer), and the session token moves
from in-memory to an http-only cookie set by the OIDC callback.
