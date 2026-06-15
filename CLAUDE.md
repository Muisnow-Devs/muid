# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

**muid** is a Go monorepo (`module sanzi.io/muid`, with a nested `sanzi.io/muid/api` module replaced to `./api` via `go.work`/`go.mod`) of gRPC microservices: **authn** (authentication flows), **authz** (authorization/tokens), **profile** (user profiles), and **mailer** (NATS → SMTP). API contracts are Protobuf under `api/proto/`; generated stubs land under `api/`.

## Primary documentation — read these first

- **[AGENTS.md](AGENTS.md)** — agent entry point: conventions, config env-var prefixes, do/don't lists.
- **[docs/ENGINEERING_GUIDE.md](docs/ENGINEERING_GUIDE.md)** — full architecture: bootstrap pattern, interceptor chain, Ent/NATS/mailer/profile/authn details.
- **[.cursor/rules/muid.mdc](.cursor/rules/muid.mdc)** — non-negotiable code rules (error handling, `infra/*` layout, protobuf opaque API, testing).
- **`.agents/skills/google-go-style/`** — Google Go style references.

**Gateways:** the HTTP/gRPC edge is three independent binaries — `cmd/gateway-public` (untrusted **HTTP** edge and the app-facing **GraphQL** BFF over authn + authz + profile: a request is deconstructed into per-service gRPC calls and the results composed. **Auth flows** — method-agnostic `startAuth`/`continueAuth` (email-OTP/OAuth/passkey, polymorphic challenge union + proof inputs) onto authn's `StartAuthSession`/`ContinueAuthSession`, plus session lifecycle `refreshSession`/`logout`/`unlinkFederatedIdentity`/`viewerSession`. **Data plane** — composed types `viewer`/`profile`/`organization` with field resolvers fanning out: authz `AuthzUserService`+`AuthzOrganizationAdminService` (orgs/roles/members/permissions) and profile `ProfileService`+`OrganizationProfileService` (profiles, avatars), schema in `api/graphql/data.graphqls`. **Tokens are httpOnly cookies, never in the GraphQL body**: the opaque session/refresh token is host-locked (`__Host-`, `SESSION_COOKIE_*`) and replayed to authn as `Session <token>` metadata; the short-lived session **access-token JWT** is a separate **subdomain-scoped** cookie (`__Secure-`, `ACCESS_TOKEN_COOKIE_NAME`/`_DOMAIN`) so other subdomains verify it via JWKS. The gateway verifies that JWT **locally** via `pkg/gateway/jwtauth` (`SESSION_ACCESS_TOKEN_ISSUER`), minting a fresh one from the session cookie on miss (`POST /security/access-token` lets subdomain apps mint proactively), then injects the verified caller id as **`x-user-id`** — the single identity key both authz (`internal/authz/grpc.UserIDMetadataKey`) and profile (`pkg/shared/authn.AuthenticatedUserIDMetadataKey`, unified to `x-user-id`) trust; backends do **not** verify tokens. Data-plane backends dialed via `AUTHZ_GRPC_ADDR` (authz **public** listener) + `PROFILE_GRPC_ADDR`; a per-request profile loader (`graph/loader`) dedupes member fan-out. In production clients may only invoke pre-registered operations from a **trusted-documents allowlist** (`GATEWAY_PUBLIC_PERSISTED_OPS_PATH`, Apollo manifest) with introspection off — `DEBUG=true` re-enables ad-hoc queries + introspection (`internal/gatewaypublic/graph/persisted`). Plus OIDC REST + JWKS, CSRF on mutations, Turnstile CAPTCHA (verified in `startAuth`), MaxMind IP-resolve, shared risk model with auth-failure feedback from `continueAuth`), `cmd/gateway-services` (trusted BFF: a **gRPC** server over the curated `ServicesGatewayService` proto — the predefined schema is the security boundary — with mTLS credentials, a JWT-auth interceptor verifying the session access token via JWKS, a rate-limit interceptor, delegating to backends with `x-user-id` attached), `cmd/gateway-internal` (ops/admin **HTTP** onto internal gRPC admin surfaces, never internet-exposed). Shared capabilities live in `pkg/gateway/*` (`risk`, `ratelimit`, `pow`, `csrf`, `httpmeta`, `jwtauth`, `mtls`, `httpx`); external drivers in `infra/geoip` (MaxMind, periodic hot-reload) and `infra/turnstile` (each with a mock variant). Env prefixes `GATEWAY_PUBLIC_`/`GATEWAY_SERVICES_`/`GATEWAY_INTERNAL_`. Contracts live under `api/`: the public GraphQL schema is `api/graphql/*.graphqls` (`schema.graphqls` auth flows + `data.graphqls` authz/profile BFF; gqlgen config + generated code + resolvers in `internal/gatewaypublic`, regenerate with `go run github.com/99designs/gqlgen generate` from `internal/gatewaypublic`); the services BFF is `api/proto/gateway/v1/services.proto` (`buf generate`).

**Known doc drift:** the old empty `cmd/gateway` placeholder was removed (superseded by the three gateways above; the root `Makefile` `SERVICES` list may still reference `gateway`). `internal/identity` has grown into subpackages (`issuer/`, `method/`, `policy/`, `resolver/`, `store/`), and authn handlers live in `internal/authn/grpc` with OIDC/passkey config parsing in `internal/authn/config`. Trust the code over the docs where they disagree.

**Authz (Casbin RBAC):** authz is the organization/permission authority, built on casbin v2 domain RBAC (domain = org UUID; shared model + permission helpers in `pkg/shared/authzmodel`). **Permission strings are `<namespace>/<resource>.<action>`** (e.g. `organization/oidc_client.write`) — the namespace is the resource domain (`organization`), not the owning service; the slash is deliberate, OIDC scopes use the colon form and must stay distinct. Rules live in the authz-owned `casbin_rule` table, written only by `internal/authz/policy.Manager` in the same tx as the relational rows (`OrganizationRole` = metadata only; `RolePermission` was removed); system roles `owner>admin>manager>member` + default grants come from a static config (`internal/authz/policy/default_policy.json`, `AUTHZ_POLICY_CONFIG_PATH`/`_JSON`) reconciled as wildcard-domain rules. Two listeners: public `AUTHZ_PORT` (`AuthzUserService` + `AuthzOrganizationAdminService`, caller identity from gateway-injected `x-user-id` metadata — authz never verifies tokens) and internal `AUTHZ_INTERNAL_PORT` (`AuthzService` service-to-service checks + relation loading, `AuthzAdminService` platform management — never gateway-exposed; authn's `AUTHN_AUTHZ_GRPC_ADDR` points here). Mutations publish `PolicyChangedEvent` on topic `authz.policy.changed`. Consuming services run a **local enforcer** via `pkg/authzclient` (namespace policies replicated, user roles cached in Redis, event-driven invalidation + periodic resync) — no per-check RPC.

**JWT signing keys:** authn **owns and rotates** the RSA signing keys via `internal/signature.SignatureManager` (GCP secret named by `AUTHN_SIGNATURE_SECRET_NAME`; `AUTHN_SIGNATURE_KEY_BITS`/`ROTATION_PERIOD_HOURS`/`PREVIOUS_GENERATIONS`). The manager is wired whenever the secret name is set; public keys (JWKS source) are served by `AuthnService.GetPublicKeys` (a gateway maps `/.well-known/jwks.json` onto it). Authz has **no** signature/secret-manager code.

**OIDC provider (OP):** authn also hosts a minimal OIDC provider — gRPC services `OIDCService` + `OIDCClientAdminService` in `api/proto/authn/v1/oidc{,_admin}.proto` (a future gateway maps spec HTTP endpoints onto them; OAuth protocol errors are *response data* (`OAuthError`), never gRPC errors). Domain logic in `internal/authn/oidc` (policy evaluator, Redis code/pending/device stores, refresh rotation with family reuse-detection, client admin), JWTs in `internal/oidctoken`, signed with the shared signing keys above. Enabled by `AUTHN_OIDC_ISSUER` (then `AUTHN_SIGNATURE_SECRET_NAME` + `AUTHN_AUTHZ_GRPC_ADDR` are required); unset = OP RPCs return Unavailable. OIDC clients belong to an authz Organization: `access_policy` public/organization/private is enforced by `internal/authn/oidc/policy` through the local authz enforcer (`LocalEnforcerAccess` over `pkg/authzclient`) and the `OIDCClientAccessGrant` allowlist; client CRUD requires the `organization/oidc_client.write` org permission (granted to admin in the static policy config, inherited by owner). `AUTHN_OIDC_CLIENTS_JSON` is unrelated (upstream IdPs for OIDC *login*, authn-as-RP).

**Session access tokens:** the opaque `session_token` (refresh-token role; the **only** credential authn RPCs accept) can be exchanged for a short-lived (≤5 min) RS256 JWT `access_token` for CDN/gateway fast-path checks — verified locally via the JWKS, never introspected. Gated by `AUTHN_SESSION_ACCESS_TOKEN_ISSUER` (+ `AUTHN_SESSION_ACCESS_TOKEN_TTL_SECONDS`, clamped to ≤300), independent of the OP but requires `AUTHN_SIGNATURE_SECRET_NAME`. Minting in `internal/authn/accesstoken` (profile claims best-effort via Profile gRPC), JWT logic in `internal/oidctoken/sessionaccess.go`; separated from OIDC tokens by header `typ "muid-session+jwt"` + claim `token_use "session"` (both verifiers reject the other kind). Issued via `IssueAccessToken` and attached to `SessionContext` at login/`ExtendSession`; it can never authorize mutations in authn.

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
