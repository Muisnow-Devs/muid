# IdP (Identity Provider) Roadmap & TODOs

This document outlines the design, architecture, and step-by-step instructions for completing the Identity Provider (IdP) capabilities in the `muid` monorepo.

For more context, mark used below use this format:

Mark | Description
---- | ----------------
[ ]  | Not implemented
[-]  | Partially implemented / in progress
[X]  | Fully implemented

## 1. Architecture Overview

- **Gateway (`cmd/gateway`)**:
  - **API Gateway**: Acts as the single entry point. Translates public requests into internal gRPC calls to `authn`, `profile`, etc.
  - **GraphQL Interface**: Serves as the primary public API for standard application interactions (e.g., frontend/mobile clients querying profile data, managing settings).
  - **OIDC REST Endpoints**: Standard OIDC strictly requires HTTP GET/POST for specific flows (like `/authorize` and `/token`). The gateway will multiplex these REST routes alongside the GraphQL endpoint.
- **Secret Management (JWK & rotation)**:
  - Uses **Google Secret Manager (GSM)**.
  - Generates, stores, and rotates RSA key pairs used for signing JWTs/OIDC tokens.
- **Admin/Internal Dashboard**:
  - Provides a secure internal UI/gateway for managing users, OAuth2 clients, and system configurations.
  - Aggregates performance analytics, login success/failure rates, risk model triggers, and general IdP observability.
- **Internal Services**:
  - **`audit`**: Asynchronous event consumer (via NATS) that logs every system change and access event for compliance, offloading write penalties from the critical path.
  - **`authn`**: Will handle core authorization grants, token generation, token validation, and identity risk modeling (e.g., dynamic PoW captcha difficulty, account soft-locking).
  - **`authz`**: Will handle scope mapping, OAuth2 client registry, user grants, permission control, and group/team management.
  - **`profile`**: Will supply claims for the OIDC `userinfo` endpoint.

---

## 2. Roadmap & Detailed TODOs

### Phase 1: Gateway Skeleton & internal gRPC routing

The gateway must safely route traffic to backend services while acting as the GraphQL server.

- [ ] **1.1 Gateway Service Bootstrapping**
  - Scaffold `cmd/gateway/main.go` using the standard `muid` bootstrapping pattern.
  - Instantiate gRPC clients (`api/proto/authn/v1`, `api/proto/profile/v1`) using existing `grpcutils` resilience/timeout logic.
  - Add standard HTTP middleware (CORS, Trace ID injection, structured logging matching `pkg/log`).
- [ ] **1.2 GraphQL Engine Integration**
  - Integrate a Go GraphQL library (e.g., `github.com/99designs/gqlgen`).
  - Create the exact schema definitions (`schema.graphql`) mirroring public use cases.
  - Implement resolvers that map GraphQL queries/mutations to backend gRPC services (e.g., `Query.me` -> `profilev1.GetProfile`).
- [ ] **1.3 Gateway Security & Context Middleware**
  - Implement API rate limiting to mitigate abuse.
  - Add security middleware (e.g., strict security headers) and CSRF validation for mutating endpoints.
  - Implement a Context Provider to extract and inject user session details into the request context before hitting the resolvers or backend.

### Phase 2: Standard OIDC Provider Endpoints

While GraphQL is the primary structural API, an IdP *must* support standard OAuth2/OIDC REST interfaces for relying parties.

- [ ] **2.1 Discovery & JWKS**
  - `GET /.well-known/openid-configuration`: Return standard OIDC capability discovery JSON.
  - `GET /jwks.json`: Serve public keys retrieved from Google Secret Manager.
- [ ] **2.2 Authorization & Token Flows**
  - `GET /authorize`: Validate `client_id`, `redirect_uri`, enforce login UI, and return Authorization Code.
  - `POST /token`: Exchange Authorization Code / Refresh Token for JWTs (Access Token, ID Token).
  - `GET /userinfo`: Return OIDC standard claims (sub, email, etc.) by extracting the Bearer token and querying the `profile` service.
  - `POST /revoke`: Standard token revocation.

### Phase 3: Google Secret Manager (GSM) Integration

All signing keys exist in Google Secret Manager. We need an interface under `infra/gsm` to interact with it.

- [-] **3.1 SecretStore Interface**
  - Define `pkg/shared/secretmanager` for symmetric/asymmetric key handling; GCP impl in `infra/secretmanager`.
  - Implement `GetLatestPrivateKey()`, `GetPublicJWKS()`.
- [ ] **3.2 Caching Layer**
  - JWKS reads from GSM should be cached in-memory or Redis (with a proper TTL) inside the gateway to prevent quota exhaustion and reduce latency for `jwks.json`.

### Phase 4: Secret Rotation Policy & Implementation

Keys must be rotated periodically (e.g., every 30-90 days, or on demand).

- [ ] **4.1 Automated Key Rotation Daemon**
  - Create a worker (e.g., a background goroutine in `authn` or a standalone cron cronjob).
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

- [ ] **6.1 Client Registry & Scope Mapping**
  - Implement database schema for storing OAuth2 Clients (`client_id`, `client_secret`, redirect URIs).
  - Implement Scope mapping (defining what internal permissions a specific OAuth2/OIDC scope grants).
- [ ] **6.2 User Grants & Delegation**
  - Track which scopes a user has explicitly granted to a specific Client (e.g., recording that user Alice granted App X the `profile:read` scope).
- [X] **6.3 Permission Control & Access Policies**
  - Implement Role-Based Access Control (RBAC) or Attribute-Based Access Control (ABAC) defining user permissions.
- [X] **6.4 Group & Team Management**
  - Develop Group/Team management, allowing users to be organized into teams.
  - Allow permissions and roles to be granted at a group level and inherited by members.

### Phase 7: Internal Management & Performance Analytics

An internal admin gateway/dashboard is necessary to monitor IdP health, analyze performance, and troubleshoot user issues.

- [ ] **7.1 Admin Gateway & API**
  - Implement a separated admin-only API (potentially under a different port or path, protected by strictly internal network rules and heavy authz).
  - Create endpoints for managing OAuth2 Clients, adjusting risk model parameters, and manually overriding user states (e.g., resolving a soft-lock).
- [ ] **7.2 Observability & Analytics Integration**
  - Expose Prometheus/OpenTelemetry metrics for login attempts, token issuance rates, error rates, and API latency.
  - Integrate distributed tracing for the gateway-to-backend flows to monitor system bottlenecks.
- [ ] **7.3 Admin UI / Dashboard**
  - Build an internal dashboard (e.g., using a frontend framework or a template-rendered Go app under `internal/templates`) to visualize performance metrics.
  - Provide UI interactions for searching audit logs, viewing connected apps per user, and viewing risk assessment statistics.

### Phase 8: Audit Log Service (Asynchronous)

An independent, event-driven service to securely record all system changes and access logs without impacting core API performance.

- [ ] **8.1 Audit Service Bootstrapping**
  - Scaffold `cmd/audit/main.go` using the standard setup and define the persistence layer (e.g., append-only Postgres tables).
- [ ] **8.2 Event Sourcing (NATS) Integration**
  - Emit lightweight events (via NATS) from `authn`, `authz`, `profile`, and `gateway` for all mutations and critical actions.
  - Develop a NATS subscriber in the `audit` service that solely listens to these topics and bulk-writes them to the datastore.
- [ ] **8.3 Query API & Retention**
  - Provide an internal gRPC API for the Admin Dashboard to query logs based on `user_id`, `client_id`, or `event_type`.
  - Implement a data retention policy/cron to archive or prune logs older than a specific threshold.

### Phase 9: Conformance & Testing

- [ ] **9.1 OIDC Conformance**
  - Write standard integration tests for full auth-code flow.
  - Use `golang.org/x/oauth2` in test setups to ensure the Gateway behaves like a standard provider.
- [ ] **9.2 Secret Rotation Testing**
  - Add mocked tests (using `infra/mocked`) ensuring tokens minted by an "old" key validate successfully if the key is still in the overlap window, and fail if the key moves to the archived state.
