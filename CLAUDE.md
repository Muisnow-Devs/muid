# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

**muid** is a Go monorepo (`module sanzi.io/muid`, with a nested `sanzi.io/muid/api` module replaced to `./api` via `go.work`/`go.mod`) of gRPC microservices: **authn** (authentication flows), **authz** (authorization/tokens), **profile** (user profiles), and **mailer** (NATS → SMTP). API contracts are Protobuf under `api/proto/`; generated stubs land under `api/`.

## Primary documentation — read these first

- **[AGENTS.md](AGENTS.md)** — agent entry point: conventions, config env-var prefixes, do/don't lists.
- **[docs/ENGINEERING_GUIDE.md](docs/ENGINEERING_GUIDE.md)** — full architecture: bootstrap pattern, interceptor chain, Ent/NATS/mailer/profile/authn details.
- **[.cursor/rules/muid.mdc](.cursor/rules/muid.mdc)** — non-negotiable code rules (error handling, `infra/*` layout, protobuf opaque API, testing).
- **`.agents/skills/google-go-style/`** — Google Go style references.

**Gateways:** the edge is three independent binaries. `cmd/gateway-public` is the untrusted HTTP edge: it serves the app-facing GraphQL auth/session API through Authn's focused `AuthenticationFlowService`, `SessionService`, and `LinkedIdentityService`; maps OIDC REST and JWKS through `OIDCService` and `SigningKeyService`; and currently composes the Authz/Profile data plane while its Phase-3 BFF migration is in progress. `cmd/gateway-services` is the curated gRPC BFF over `ServicesGatewayService`. `cmd/gateway-internal` is the internal-only admin HTTP edge and requires both an authenticated `admin-ingress` workload and live platform authorization.

All gateway-to-backend gRPC is mTLS. `pkg/mtls` loads certificates and roots; `pkg/grpc_utils` verifies an exact `spiffe://muid/service/<workload>` URI SAN and installs a typed `RequestPrincipal` according to the per-method workload/user policy. A backend accepts `x-user-id` only after that workload policy authorizes the caller; raw metadata is never independently trusted. The public gateway verifies short-lived session JWTs locally from Authn JWKS before delegating a user. Browser credentials remain HttpOnly cookies: a host-locked opaque session cookie and a subdomain-scoped access-token cookie. GraphQL mutations are CSRF-protected, production operations use a trusted-document allowlist, and Turnstile/MaxMind/rate/risk controls run at the public edge.

Shared gateway capabilities live under `pkg/gateway/*` (`risk`, `ratelimit`, `pow`, `csrf`, `httpmeta`, `jwtauth`, `httpx`); external drivers live in `infra/geoip` and `infra/turnstile`. Environment prefixes are `GATEWAY_PUBLIC_`, `GATEWAY_SERVICES_`, and `GATEWAY_INTERNAL_`. Contracts live under `api/graphql/*.graphqls` and `api/proto/gateway/v1/services.proto`; use the pinned `make graphql` and `make proto` generation targets.

**Known doc drift:** the old empty `cmd/gateway` placeholder was removed (superseded by the three gateways above; the root `Makefile` `SERVICES` list may still reference `gateway`). `internal/identity` has grown into subpackages (`issuer/`, `method/`, `policy/`, `resolver/`, `store/`), and authn handlers live in `internal/authn/grpc` with OIDC/passkey config parsing in `internal/authn/config`. Trust the code over the docs where they disagree.

**Authz (Casbin RBAC):** authz is the organization/permission authority, built on casbin v2 domain RBAC (domain = org UUID; shared model + permission helpers in `pkg/shared/authzmodel`). **Permission strings are `<namespace>/<resource>.<action>`** (e.g. `organization/oidc_client.write`) — the namespace is the resource domain (`organization`), not the owning service; the slash is deliberate, OIDC scopes use the colon form and must stay distinct. Rules live in the authz-owned `casbin_rule` table, written only by `internal/authz/policy.Manager` in the same tx as the relational rows (`OrganizationRole` = metadata only; `RolePermission` was removed); system roles `owner>admin>manager>member` + default grants come from a static config (`internal/authz/policy/default_policy.json`, `AUTHZ_POLICY_CONFIG_PATH`/`_JSON`) reconciled as wildcard-domain rules. Two listeners: public `AUTHZ_PORT` (`AuthzUserService` + `AuthzOrganizationAdminService`, caller identity from gateway-injected `x-user-id` metadata — authz never verifies tokens) and internal `AUTHZ_INTERNAL_PORT` (`AuthzService` service-to-service checks + relation loading, `AuthzAdminService` platform management — never gateway-exposed; authn's `AUTHN_AUTHZ_GRPC_ADDR` points here). Mutations publish `PolicyChangedEvent` on topic `authz.policy.changed`. Consuming services run a **local enforcer** via `pkg/authzclient` (namespace policies replicated, user roles cached in Redis, event-driven invalidation + periodic resync) — no per-check RPC.

**JWT signing keys:** authn **owns and rotates** the RSA signing keys via `internal/signature.SignatureManager` (GCP secret named by `AUTHN_SIGNATURE_SECRET_NAME`; `AUTHN_SIGNATURE_KEY_BITS`/`ROTATION_PERIOD_HOURS`/`PREVIOUS_GENERATIONS`). The manager is wired whenever the secret name is set; public keys (JWKS source) are served by `SigningKeyService.GetPublicKeys` (a gateway maps `/.well-known/jwks.json` onto it). Authz has **no** signature/secret-manager code.

**OIDC provider (OP):** authn also hosts a minimal OIDC provider — gRPC services `OIDCService` + `OIDCClientAdminService` in `api/proto/authn/v1/oidc{,_admin}.proto` (a future gateway maps spec HTTP endpoints onto them; OAuth protocol errors are *response data* (`OAuthError`), never gRPC errors). Domain logic in `internal/authn/oidc` (policy evaluator, Redis code/pending/device stores, refresh rotation with family reuse-detection, client admin), JWTs in `internal/oidctoken`, signed with the shared signing keys above. Enabled by `AUTHN_OIDC_ISSUER` (then `AUTHN_SIGNATURE_SECRET_NAME` + `AUTHN_AUTHZ_GRPC_ADDR` are required); unset = OP RPCs return Unavailable. OIDC clients belong to an authz Organization: `access_policy` public/organization/private is enforced by `internal/authn/oidc/policy` through the local authz enforcer (`LocalEnforcerAccess` over `pkg/authzclient`) and the `OIDCClientAccessGrant` allowlist; client CRUD requires the `organization/oidc_client.write` org permission (granted to admin in the static policy config, inherited by owner). `AUTHN_OIDC_CLIENTS_JSON` is unrelated (upstream IdPs for OIDC *login*, authn-as-RP).

**Session access tokens:** the opaque `session_token` (refresh-token role; the **only** credential authn RPCs accept) can be exchanged for a short-lived (≤5 min) RS256 JWT `access_token` for CDN/gateway fast-path checks — verified locally via the JWKS, never introspected. Gated by `AUTHN_SESSION_ACCESS_TOKEN_ISSUER` (+ `AUTHN_SESSION_ACCESS_TOKEN_TTL_SECONDS`, clamped to ≤300), independent of the OP but requires `AUTHN_SIGNATURE_SECRET_NAME`. Minting in `internal/authn/accesstoken` (profile claims best-effort via Profile gRPC), JWT logic in `internal/oidctoken/sessionaccess.go`; separated from OIDC tokens by header `typ "muid-session+jwt"` + claim `token_use "session"` (both verifiers reject the other kind). Issued via `SessionService.IssueAccessToken` and attached to `SessionContext` at login/`SessionService.RefreshSession`; it can never authorize mutations in authn.

## Commands

```sh
# Protobuf codegen (Buf; regenerates *.pb.go under api/)
buf build
buf generate --template buf.gen.yaml      # or: make proto

# Ent codegen (after editing internal/<service>/ent/schema)
go generate ./internal/authn/ent/...
go generate ./internal/profile/ent/...
go generate ./internal/authz/ent/...

# Build a service (make build cross-compiles linux/amd64; use plain go build locally)
go build -o bin/authn ./cmd/authn         # same for authz, profile, mailer

# Tests
go test ./...                             # full sweep from repo root
go test ./internal/profile/updatemask/    # single package
go test -run TestName ./internal/authn/app/   # single test

# Mailer manual-test NATS publishers
make test-publish-tools                   # builds cmd/test/test-publish-* into bin/
```

There is no lint config in the repo; `go vet ./...` is the baseline check.

## Architecture (big picture)

Every service follows the same four-layer bootstrap shape — when adding anything, match an existing service rather than inventing a new pattern:

1. `cmd/<service>/main.go` — load config via `pkg/shared.LoadConfig[app.Config](app.ConfigEnvPrefix)` (envconfig; env vars are `AUTHN_`/`AUTHZ_`/`PROFILE_`/`MAILER_` + field tag), construct infra, start, graceful shutdown.
2. `internal/<service>/app/config.go` — envconfig struct.
3. `internal/<service>/app/bootstrap.go` — open NATS/Redis/R2/SMTP/Postgres (`pkg/entpostgres.OpenEntPostgres` for Ent), cleanup via `pkg/errutil`.
4. `internal/<service>/app/service.go` — gRPC server with the standard interceptor chain: Trace → OTel tracing (`pkg/shared/tracing` + `infra/otel`, noop when nil) → protovalidate → service request-context → Recovery → Logger → Timeout.

Key boundaries:

- **`infra/<backend>/`** (redis, nats, smtp, r2, otel, secretmanager, mocked) — generic drivers only. `interface.go` holds *only* exported interfaces/config; implementations in sibling files; stable errors in `errors.go`. Authn-coupled adapters (OTP, transition store, identity providers) live under `internal/authn/`, never top-level `infra/`.
- **`pkg/`** — shared libs: `pkg/log` (trace-id logging — always use this, never stdlib `log`), `pkg/grpc_utils`, `pkg/sqldb`/`pkg/entpostgres`/`pkg/enttx`, `pkg/errutil`, `pkg/validation`, `pkg/shared` (config, pubsub, topics, tracing contracts).
- **`internal/session`** — typed auth-transition state (`AuthFlowKind`: email_otp/oidc/passkey with typed pointers, not `map[string]any`); Redis backing in `internal/authn/kv`.
- **`internal/identity`** — identity-provider abstraction (issuer/method/policy/resolver/store) consumed by authn.
- **Cross-service comms:** gRPC (authn → profile `CreateProfile`, dialed with `log.UnaryClientInterceptor()` to forward `x-trace-id`) and NATS pub/sub (`pkg/shared/pubsub.PubSub`, topics in `pkg/shared/topics`, protobuf-marshaled payloads). Mailer consumes topics via the `TopicHandler` pattern in `internal/mailer/handlers/<event>/`.

## Non-negotiable conventions (summary — full detail in .cursor/rules/muid.mdc)

- **Protobuf opaque API:** build messages with `&pb.T{}` + `Set*`/`Get*`/`Has*`; never `new(pb.T)` or `*_builder` as default style.
- **Errors:** inner layers use sentinels/typed errors/`errors.Join`, not `fmt.Errorf("%w")` chains (one wrap allowed at `cmd/*/main` boundaries). At RPC boundaries, unexpected failures → `log.LogUnexpected` with `slog.Attr` (use `log.ProfileID`/`UserID`/`TransitionID` taking `uuid.UUID`) and return `grpcutils.GRPCInternalError()`. Never leak raw errors or protovalidate violations into client-visible status messages. Multiple error checks: assign-then-check, flat early-return branches.
- **Cleanup:** `errutil.Discard`/`Close`/`CloseIf`, not ad-hoc `_ = x.Close()`.
- **Reuse before duplication:** extend `pkg/*`/`infra/*` instead of adding parallel small copies of the same concern.
- **Profile specifics:** `UserAvatar` rows are append-only INSERTs (never mutate history); username changes go through `pkg/validation.ValidUsername` and are lowercased for storage; avatar ingest (`internal/profile/avataringest`) is async — never awaited inside the `CreateProfile` handler.
- **Tests:** table-driven, `t.Run` subtests, `t.Parallel()` where safe; keep pure-logic packages (e.g. `internal/profile/updatemask`) free of Ent/DB imports.
