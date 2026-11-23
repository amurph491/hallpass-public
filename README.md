# Hallpass

Hallpass is an authorization and brokered-execution layer for AI agents.

An agent never holds a provider credential. It asks Hallpass to perform one operation. Hallpass checks whether
the agent's delegated authority covers that exact operation, and only then does a trusted executor resolve the
server-side credential and call the provider (Slack, GitHub, Linear, Notion, Google Drive, Gmail, HubSpot).

```text
 MCP client ──stdio──▶ bridge ──HTTPS + agent credential──▶ Hallpass API
                                                               │
                         authenticate ─▶ resolve resource ─▶ pure kernel decision
                                                               │ Allow / Deny / RequireApproval
                                                               ▼
                         single-use lease ─▶ trusted executor (tenant gate held)
                                                               │ revalidate · resolve credential · dispatch · audit
                                                               ▼
                                                            Provider
```

**Start with [docs/system-design.md](docs/system-design.md)** for a worked example, the authorization path,
and the tradeoffs around revocation, provider failures, and scaling.

## Core ideas

- **Authority is delegated.** A human grants an agent a subset of their authority over specific resources, actions,
  and constraints. An agent can re-delegate to a subagent, but only with less authority, never more.
- **The authorization kernel is a pure function**: `policies + delegation chain + request + time → Allow | Deny |
  RequireApproval`. It does no I/O, and the type system prevents forging its successful result.
- **Revocation is coordinated across replicas.** Executions hold a shared tenant gate through dispatch. Revocation
  commits under the exclusive gate, so later executions revalidate against the updated authority. The design describes
  the remaining race if the gate session is lost just before dispatch.
- **Fail closed.** Unknown tools, unselected resources, missing facts, and infrastructure errors never result in an
  allowed call.

## Repository layout

| Path | Contents |
|---|---|
| `kernel/` | Pure domain model and authorization engine (no infrastructure dependencies) |
| `application/` | Orchestration and ports: tool pipeline, trusted executor, leases, tenant gate, approvals |
| `adapters/` | PostgreSQL (Doobie, Flyway, RLS), envelope secret store, OIDC, provider connectors |
| `gateway/` | HTTP runtime, configuration, production guard, OpenTelemetry, operator CLIs |
| `bridge/` | Local stdio MCP adapter that calls the agent API with an agent credential |
| `demo-admin/` | Admin UI (React + TypeScript): agents, grants, connections, approvals, activity |
| `deploy/` | Kubernetes base and example overlay, alert rules |

Scala 3 on Cats Effect, http4s, Doobie, and PostgreSQL 18.

## Build and test

Requires JDK 21, sbt, Node.js 20+, and Docker (the PostgreSQL suites use Testcontainers).

```bash
sbt -batch \
  "bridge/stageRuntimeClasspath" \
  "kernel/testOnly *Suite" \
  "application/testOnly *Suite" \
  "adapters/testOnly *Suite" \
  "gateway/testOnly *Suite" \
  "bridge/testOnly *Suite"
```

The plain `sbt test` task does not select the MUnit suites in this build, so use the explicit command above. If Docker
is not available, the PostgreSQL suites are skipped rather than failed.

```bash
cd demo-admin && npm ci && npm test && npm run build
```

## Run locally

```bash
umask 077
mkdir -p .secrets
openssl rand -base64 32 > .secrets/secret_master_key
openssl rand -base64 48 > .secrets/admin_bootstrap
printf 'active_key_id=local-v1\nkey.local-v1=%s\n' "$(openssl rand -base64 32)" > .secrets/agent_credential_keys
openssl rand -base64 32 > .secrets/db_password
printf '%s\n' 'unused-unless-oauth-is-configured' > .secrets/slack_client_secret
for f in oidc_client_secret otlp_headers github_app_private_key.pem github_client_secret \
         linear_client_secret notion_client_secret google_drive_client_secret hubspot_client_secret; do
  : > ".secrets/$f"
done
docker compose -f compose.demo.yml up --build
```

The admin UI is served at http://localhost:3000; sign in with the value in `.secrets/admin_bootstrap`. The agent API
listens on `127.0.0.1:8081`. Both bind to loopback only. Connecting a real provider requires that provider's OAuth app
credentials. The empty secret files hold optional credentials that are read only when the matching provider is
configured.
