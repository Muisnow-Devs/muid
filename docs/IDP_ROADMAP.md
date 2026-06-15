# IdP (Identity Provider) Roadmap & TODOs

This document outlines the design, architecture, and step-by-step instructions for completing the Identity Provider (IdP) capabilities in the `muid` monorepo.

For more context, mark used below use this format:

Mark | Description
---- | ----------------
[ ]  | Not implemented
[-]  | Partially implemented / in progress
[X]  | Fully implemented

> **Status snapshot (last scan):** The backend gRPC services carry most of the IdP weight today — OIDC provider logic, RSA signing-key ownership & rotation, Casbin RBAC org/role/membership, OIDC client administration, and immutable audit logging are all implemented inside `authn`/`authz`/`profile`. The **gateway edge now exists** as three independent binaries — `cmd/gateway-public` (untrusted HTTP edge: app-facing GraphQL for auth flows + OIDC REST + JWKS, CSRF, Turnstile, MaxMind IP-resolve, risk model), `cmd/gateway-services` (trusted gRPC BFF: mTLS, JWT auth, rate limiting), and `cmd/gateway-internal` (ops/admin HTTP onto the internal admin RPCs) — sharing `pkg/gateway/*` capabilities and the `infra/geoip`/`infra/turnstile` drivers. The remaining OIDC REST endpoints beyond discovery/JWKS/token/userinfo (full authorize/device/consent flows) are still to be wired onto the existing gRPC. The audit subsystem was implemented as **per-service, same-transaction immutable tables** rather than the originally-planned async NATS consumer (see Phase 8).

## 1. Architecture Overview

- **Gateways** — *implemented as three independent binaries* (`cmd/gateway-public`, `cmd/gateway-services`, `cmd/gateway-internal`):
  - **Public gateway**: untrusted-internet entry point. Serves the app-facing **GraphQL** API for authentication flows (`startLogin`/`continueLogin`/`resendLoginOtp` → authn's `StartAuthSession`/`ContinueAuthSession`) and maps the OIDC REST + JWKS surface, all behind the abuse-protection middleware (rate limiting, risk model, CSRF, Turnstile CAPTCHA, MaxMind IP-resolve). The GraphQL schema contract lives at `api/graphql/schema.graphqls`.
  - **Services gateway (gRPC BFF)**: the trusted frontend BFF — a gRPC server over the curated `ServicesGatewayService` proto (the predefined schema is the security boundary, e.g. `GetMe` → `profilev1.GetProfile`), terminating mTLS from the edge, verifying session-access-token JWTs locally, and delegating to backends with the verified identity attached.
  - **Internal gateway**: ops/admin edge onto the internal admin gRPC surfaces; never internet-exposed.
  - Shared capabilities: `pkg/gateway/{risk,ratelimit,pow,csrf,httpmeta,jwtauth,mtls,httpx}`; external drivers `infra/geoip` (MaxMind, hot-reload) + `infra/turnstile`.
- **Secret Management (JWK & rotation)** — *implemented in `authn`*:
  - Uses **Google Secret Manager (GSM)** via `infra/secretmanager` (contract in `pkg/shared/secretmanager`).
  - Generates, stores, and rotates RSA key pairs used for signing JWTs/OIDC tokens (`internal/signature`).
- **Admin/Internal Dashboard** — *gRPC admin services exist; no UI/HTTP admin gateway yet*:
  - Provides a secure internal UI/gateway for managing users, OAuth2 clients, and system configurations.
  - Aggregates performance analytics, login success/failure rates, risk model triggers, and general IdP observability.
- **Internal Services**:
  - **`audit`**: *Implemented differently than originally planned* — instead of a standalone async consumer, every state-changing mutation in `authn`, `authz`, and `profile` writes an immutable, structured audit record into that service's own append-only Postgres table, **in the same transaction as the change** (atomic, no loss). A separate NATS-based aggregation/query service remains a future option (see Phase 8).
  - **`authn`**: Handles core auth flows, OIDC provider logic, token generation/validation, and owns/rotates the JWT signing keys. Identity risk modeling (PoW captcha, soft-locking) is not yet implemented.
  - **`authz`**: Handles permission control and group/team management via Casbin domain RBAC (organizations, roles, memberships). OIDC clients are owned by an `authz` Organization but stored in `authn`.
  - **`profile`**: Supplies claims for the OIDC `userinfo` endpoint.

---

## 2. Roadmap & Detailed TODOs

### Phase 1: Gateway Skeleton & internal gRPC routing

The gateways must safely route traffic to backend services: the public gateway serves the app-facing GraphQL API (auth flows) and OIDC REST, while the services gateway acts as the curated gRPC BFF.

> The three gateway binaries are scaffolded and wired; remaining work is breadth (more OIDC endpoints, richer BFF surface).

- [X] **1.1 Gateway Service Bootstrapping**
  - All three gateways (`cmd/gateway-{public,services,internal}/main.go`) follow the standard `muid` bootstrap pattern (`internal/gateway*/app`).
  - gRPC clients to `authn`/`profile`/`authz` are dialled via `grpcutils.DialInsecureClient` with resilience config; a graceful HTTP server wrapper lives in `pkg/gateway/httpx`.
  - Shared HTTP middleware (CORS, Trace ID injection, structured `pkg/log` logging, panic recovery, security headers) in `pkg/gateway/httpx`.
- [-] **1.2 App API (GraphQL on public, gRPC BFF on services — both predefined schemas)**
  - Public gateway: gqlgen GraphQL at `/graphql` over `api/graphql/schema.graphqls` (generated code + resolvers in `internal/gatewaypublic/graph`). Covers the basic email-OTP login flow — `startLogin`/`continueLogin`/`resendLoginOtp` → authn's `StartAuthSession`/`ContinueAuthSession`; CSRF-enforced, Turnstile-verified on start, auth failures fed back into the risk tracker. Broader coverage (passkey/OAuth methods, profile/settings) still to add.
  - Services gateway: a gRPC server over the curated `ServicesGatewayService` proto (`api/proto/gateway/v1/services.proto`); `GetMe` → `profilev1.GetProfile` forwarding the JWT-verified `x-user-id`. Both narrow, predefined schemas are the security boundary.
- [X] **1.3 Gateway Security & Context Middleware**
  - Redis-backed rate limiting (`pkg/gateway/ratelimit`), risk model with PoW/block decisions (`pkg/gateway/risk` + `pow`), CSRF validation (`pkg/gateway/csrf`), strict security headers, and a context provider (`pkg/gateway/httpmeta` + `internal/gatewaypublic/reqctx` / `internal/gatewayservices/authctx`) injecting verified identity/IP/geo into request + outgoing gRPC metadata.

### Phase 2: Standard OIDC Provider Endpoints

Beyond the curated gRPC BFF, an IdP *must* support standard OAuth2/OIDC REST interfaces for relying parties (served by the public gateway).

> The OIDC logic is fully implemented as gRPC in `authn` (`OIDCService` in `api/proto/authn/v1/oidc.proto`, handlers in `internal/authn/grpc/oidc_handler.go`). What's missing is the HTTP/REST surface, which the (unbuilt) gateway must map onto these RPCs.

- [X] **2.1 Discovery & JWKS** — *REST mapping live in `cmd/gateway-public`*
  - `GET /.well-known/openid-configuration` → `OIDCService.GetProviderMetadata` (`internal/gatewaypublic/app/oidc.go`).
  - `GET /.well-known/jwks.json` → `AuthnService.GetPublicKeys` (rendered as a JWKS document).
- [-] **2.2 Authorization & Token Flows** — *token + userinfo mapped; authorize/device pending*
  - `POST /oidc/token` → `OIDCService.ExchangeToken` (authorization_code + refresh_token grants; OAuth errors rendered as response data, never gRPC-error leakage).
  - `GET|POST /oidc/userinfo` → `OIDCService.GetUserInfo` (Bearer access token).
  - `GET /authorize` (+ `DecideConsent`, device-code `StartDeviceAuthorization`, etc.) and `POST /revoke`/`introspect`: gRPC backing exists; REST mapping still to wire.

### Phase 3: Google Secret Manager (GSM) Integration

All signing keys exist in Google Secret Manager. We need an interface under `infra/secretmanager` to interact with it.

- [X] **3.1 SecretStore Interface**
  - Contract in `pkg/shared/secretmanager`; GCP implementation in `infra/secretmanager` (with `infra/mocked`/fake for tests).
  - Latest-version reads and JWKS-source public keys are served through `internal/signature`.
- [-] **3.2 Caching Layer**
  - `authn`'s `SignatureManager` already holds active + previous key generations in memory, so `GetPublicKeys`/JWKS does not hit GSM per request.
  - A dedicated gateway-side (in-memory or Redis, TTL'd) JWKS cache is still pending (blocked on the gateway).

### Phase 4: Secret Rotation Policy & Implementation

Keys must be rotated periodically (e.g., every 30-90 days, or on demand).

- [X] **4.1 Automated Key Rotation Daemon** — *implemented in `authn` (`internal/signature`), not the gateway*
  - Background rotation ticker (`RotationPeriod`, default 30d) with `PreviousGenerations` kept available for validation overlap.
  - **Policy Rules**:
    1. **Pre-generation**: Generate new Key A (Next) while Key B (Current) is still active (e.g., 24h before switch).
    2. **Active overlap**: Publish both Key A and Key B in `/jwks.json` to allow relying parties to cache them.
    3. **Switch**: Promote Key A to handle new signatures; Key B remains in JWKS for validation of old tokens until their expiry.
    4. **Purge/Archive**: Remove Key B from `/jwks.json` and optionally destroy it in GSM after maximum token TTL expires.
- [X] **4.2 Rotation Logic inside `infra/secretmanager`**
  - Implement logic using `google.golang.org/api/secretmanager/v1`. Create new Secret Versions for new RSA keys. Disable/Destroy old versions.

### Phase 5: OIDC Specifics in `authn` Service

The `authn` service must actually process the OIDC core logic (rather than the gateway, which is stateless).

- [X] **5.1 OIDC State Management**
  - Add OIDC Session/Grant storage (likely in Postgres via `pkg/entpostgres` or Redis). We need to store `auth_code` and PKCE (`code_challenge`) state during the `/authorize` -> `/token` exchange.
- [X] **5.2 ID Token Generation**
  - Implement strict JWT generation complying with the OIDC standard (correct `iss`, `aud`, `exp`, `iat`, `nonce` claims).
  - Sign tokens using the current Active Private Key from GSM.
- [ ] **5.3 Risk Model & Abuse Prevention**
  - Implement an internal risk scoring model to evaluate incoming authentication attempts.
  - Dynamically adjust Proof-of-Work (PoW) CAPTCHA difficulty based on the assessed risk.
  - Apply soft-locking mechanisms to user accounts upon detecting highly suspicious or brute-force behavior.
  
### Phase 6: Authorization (`authz`) Service & Scope Management

The `authz` service handles fine-grained access control, OAuth2 clients, and user delegation.

- [-] **6.1 Client Registry & Scope Mapping**
  - OAuth2 client registry is fully implemented (`client_id`, secrets, redirect URIs, scopes, grant types, access policy) — stored in `authn` (`OIDCClient` and friends), owned by an `authz` Organization, administered via `OIDCClientAdminService` / `internal/authn/oidc/admin.go`.
  - Explicit mapping of OIDC scopes onto internal `authz` permissions is not yet a distinct feature (OIDC scopes use the colon form and are deliberately kept distinct from authz's slash-form permissions).
- [X] **6.2 User Grants & Delegation**
  - Per-user consent grants are tracked (`OIDCGrant`), surfaced/revocable via `ListGrantedConsents` / `RevokeConsent`, plus the `OIDCClientAccessGrant` allowlist.
- [X] **6.3 Permission Control & Access Policies**
  - Implement Role-Based Access Control (RBAC) or Attribute-Based Access Control (ABAC) defining user permissions.
- [X] **6.4 Group & Team Management**
  - Develop Group/Team management, allowing users to be organized into teams.
  - Allow permissions and roles to be granted at a group level and inherited by members.

### Phase 7: Internal Management & Performance Analytics

An internal admin gateway/dashboard is necessary to monitor IdP health, analyze performance, and troubleshoot user issues.

- [-] **7.1 Admin Gateway & API**
  - Admin-only gRPC surfaces already exist on internal listeners (`OIDCClientAdminService`, `AuthzAdminService`, `AuthzOrganizationAdminService`) — never gateway-exposed.
  - A consolidated admin HTTP API (separate port/path, internal-only) and risk/soft-lock override endpoints are still pending.
- [-] **7.2 Observability & Analytics Integration**
  - OpenTelemetry tracing is wired across services (`infra/otel` + the standard interceptor chain).
  - Prometheus/OTel **metrics** (login attempts, token issuance, error/latency) are not yet exposed, and gateway-to-backend tracing awaits the gateway.
- [ ] **7.3 Admin UI / Dashboard**
  - Build an internal dashboard (e.g., using a frontend framework or a template-rendered Go app under `internal/templates`) to visualize performance metrics.
  - Provide UI interactions for searching audit logs, viewing connected apps per user, and viewing risk assessment statistics.

### Phase 8: Audit Logging

> **Design change:** Audit was implemented as **per-service, immutable, same-transaction tables** instead of a standalone async NATS-consumer service. Each of `authn`, `authz`, and `profile` owns an append-only `AuditLog` Ent table (all fields immutable, mirroring the `UserAvatar` append-only pattern). The audit row is INSERTed inside the **same `enttx.Run` transaction** as the mutation it describes, so a record can never outlive a rolled-back change nor a change escape unrecorded. The shared contract (action vocabulary, change-payload encoding, actor/trace plumbing) lives in `pkg/audit`; per-service glue in `internal/authz/policy/audit.go`, `internal/profile/core/audit.go`, and `internal/authn/authnaudit`. Secrets/hashes/tokens are never written to the change payload.

- [-] **8.1 Audit Persistence**
  - Done as per-service append-only Postgres tables (not a standalone `cmd/audit` service): authz mutations (org/role/member/raw-rule), profile mutations (profile, org-profile, avatar), and authn OIDC-client admin + `RevokeFederatedIdentity`/`RevokeConsent`.
  - Intentionally **not yet audited** in `authn` (they flow through abstractions that own their own persistence): `RevokeSession`, `RevokeToken`, and login-path `session.create` / `identity.link`.
- [ ] **8.2 Async Event Sourcing (NATS) Aggregation** — *deliberately deferred*
  - The current design writes audit records synchronously in-transaction. A future enhancement could additionally emit lightweight NATS events for an external SIEM/aggregator (the original "separate audit consumer" plan).
- [ ] **8.3 Query API & Retention**
  - Provide an internal gRPC API for the Admin Dashboard to query logs based on `user_id`, `organization_id`, `resource`, or `action`.
  - Implement a data retention policy/cron to archive or prune logs older than a specific threshold.

### Phase 9: Conformance & Testing

- [-] **9.1 OIDC Conformance**
  - The OIDC provider has unit/integration coverage in `internal/authn/oidc` (e.g., `provider_test.go`).
  - A standard end-to-end auth-code-flow harness using `golang.org/x/oauth2` is still pending (and needs the gateway's REST surface to exercise it like a real provider).
- [-] **9.2 Secret Rotation Testing**
  - Rotation/overlap is covered by `internal/signature/manager_test.go` and `infra/secretmanager` tests using `infra/mocked` fakes.
  - The full scenario (token minted by an "old" key validates during overlap, then fails once archived) is not yet asserted end-to-end.
