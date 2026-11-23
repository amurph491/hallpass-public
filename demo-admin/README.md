# Hallpass admin UI

The control plane manages agents, capability grants, keys, app connections, and authorization/execution evidence. Home, Agents, Apps, and Activity share the light/dark design system. Slack message search is the implemented provider execution path.

Agents, grants, revocations, credential verifier metadata, browser sessions, and audit evidence are durable PostgreSQL state. Provider credentials remain on the server behind the trusted executor. Enrollment and rotation disclose an **Hallpass agent key once**; the browser keeps that plaintext only in its protected disclosure dialog, never in local storage or the query cache. Pending issuance cannot be dismissed accidentally. The agent key authenticates the agent and grants no provider authority by itself.

## Development

Use WSL-native Node.js 22 or newer and the root Compose stack for the complete local flow. For frontend-only work:

```bash
npm ci
npm run dev
npm test
npm run build
```

Vite proxies `/api` to `http://localhost:8080` by default. Set `HALLPASS_API_PROXY=http://localhost:3000` to reach Compose. Configure the server's `HALLPASS_ADMIN_ORIGIN` to the browser's exact origin when using a different development port; the default is `http://localhost:3000`.

## Sign-in and workspace lifecycle

On load or an OIDC/Slack OAuth return, `/api/session` restores the durable HttpOnly session and its derived CSRF token. `/api/auth/methods` determines which sign-in choices appear. OIDC uses a top-level navigation to `/api/auth/oidc/start`; the server handles authorization code with PKCE and the callback. The development bootstrap form appears only when that method is configured. Production refuses development bootstrap login.

Signing in proves identity. Current administrator membership is required to open a workspace; the server rebuilds the authenticated human and enforces ADMIN access on every management request. Workspace labels and emergency elevation come from verified session metadata. The UI offers workspace selection and sign-out and returns to the gate on session expiry. It makes no fixed session-duration promise.

The query cache belongs to the mounted user/workspace session. Switching workspace, signing out, or expiry retires that cache and transient dialogs. Late responses from a previous workspace cannot populate the new workspace's cache or replace its CSRF token. The server resolves the trusted tenant; capability and authorization forms cannot select an arbitrary tenant.

## Source layout and routes

```text
src/
  main.tsx          entry and router
  app/              session lifecycle, admin shell, sidebar, search, routes
  features/         screen and dialog workflows
  lib/              pure presentation and domain-display helpers
  ui/               shared Button, Pill, Card, Field, Dialog, and feedback
  styles/           light/dark tokens and application styles
  api/client.ts     same-origin fetch, CSRF, session APIs, normalization
  api/queries.ts    credential-free reads within the active workspace cache
```

Home is `/admin`; lists are `/admin/agents`, `/admin/apps`, and `/admin/activity`. Agent detail is `/admin/agents/<id>` with `?tab=key|setup|activity`; app detail is `/admin/apps/<resource id>`. A request opens through `?request=<id>`. Older hash links and retired sections redirect to their current screen, including the Slack OAuth callback's `#connections`. Paths outside `/admin` redirect to Home.

Global search supports Ctrl/Cmd+K, Arrow Up/Down, Enter for the active result, and Escape. Entity navigation resets detail dialogs and pending preview results. Access tests record a human preview and never execute provider actions. Partial grant writes report their saved progress and retry only unfinished capabilities. Removing one delegation leaves any other applicable grants in effect.

Client labels and manual file paths are per-browser display preferences, never authenticated identity. Setup commands contain agent IDs and client names, never a key. First import and local replacement commands are distinct; the local file determines whether `--rotate` is needed. Durable per-agent completion evidence survives the recent-history limit. History outages show Retry instead of implying the client still needs setup. Home attention counts describe the loaded recent window, not complete time-range aggregates.

## Deployment

Build `demo-admin/Dockerfile` with `--target production` for static files served by unprivileged nginx on port 8080. The ingress routes `/api/` on the same HTTPS host to the management listener; the production UI image does not proxy to a demo API. See `deploy/kubernetes/overlays/example` and `docs/production-deployment-design.md` for the deployment boundary.

The default Docker target is the local Compose demo, whose nginx proxies `/api/` internally. Keep the local UI and agent listener bound to host loopback. Passing `ProductionGuard` is necessary for production; deployment exit criteria still require live evidence.

## Server contract

All browser calls use relative, same-origin endpoints:

```text
GET  /api/auth/methods
GET  /api/auth/oidc/start
GET  /api/auth/oidc/callback                 (server-handled redirect)
POST /api/admin/session                      (configured development only)
GET  /api/session
POST /api/session/tenant
POST /api/session/logout
GET  /api/agents
POST /api/agents
GET  /api/agents/{id}/credentials
POST /api/agents/{id}/credentials
POST /api/agents/{id}/credentials/{keyId}/rotate
POST /api/agents/{id}/credentials/{keyId}/revoke
GET  /api/resources
GET  /api/capabilities
GET  /api/tools
GET  /api/delegations
POST /api/delegations
POST /api/delegations/{id}/revoke
GET  /api/connections
POST /api/connections/slack/start
GET  /api/oauth/slack/callback                (server-handled redirect)
POST /api/connections/{id}/disconnect
POST /api/authorization/check
GET  /api/authorization/decisions
GET  /api/executions                         (?agentId, limit, cursor)
GET  /api/executions/{requestId}             (?agentId, limit, cursor)
GET  /api/executions/summary                 (optional ?agentId)
```

Unsafe management requests carry the restored CSRF token. Workspace selection is validated against current membership. The completion summary reads the durable tenant-scoped journal; an optional agent filter narrows it further. Infrastructure failures return unavailable, never false completion evidence. A request-history failure has distinct unavailable feedback and Retry; it is not a recorded `COMPLETION_UNKNOWN` outcome.

## Browser regression checks

`tests/browser-regressions.mjs` runs Chromium against a running Vite server with a fake same-origin API. Use a WSL Playwright installation and its Chromium browser:

```bash
# In another terminal, run npm run dev -- --host 127.0.0.1 --port 5189
ADMIN_TEST_URL=http://127.0.0.1:5189 node tests/browser-regressions.mjs
```

If Playwright is installed outside this package, set `PLAYWRIGHT_MODULE` to its absolute module path. The checks use fake keys, sessions, and provider data. Unit/build/browser checks do not establish live OIDC or Slack compatibility.
