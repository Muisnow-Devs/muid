# Gateway Data-Plane Boundary

Status: Planned

Classification: S/B (edge protocol and responsibility redesign)

# Problem

`gateway-public` combines browser authentication/OIDC with a broad authenticated
Authz/Profile GraphQL implementation, while `gateway-services` independently
authenticates access tokens and exposes `GetMe`. The browser API must retain its
GraphQL and HttpOnly-cookie contract, but its product resolvers should not form
a second Authz/Profile BFF.

# Evidence

- `api/graphql/schema.graphqls` and generated gateway-public resolvers include
  login/session operations plus user, organization, role, member, and profile
  data operations.
- `internal/gatewaypublic/app/bootstrap.go` dials Authn, Authz, and Profile.
- `internal/gatewaypublic/graph/data.resolvers.go` contains authenticated Authz
  and Profile query/mutation forwarding.
- `internal/gatewaypublic/graph/loader/loader.go` composes organization members
  with Profile lookups.
- `api/proto/gateway/v1/services.proto` defines
  `ServicesGatewayService.GetMe`.
- `internal/gatewayservices/app/interceptors.go` independently verifies JWTs,
  and `internal/gatewayservices/grpc/handler.go:GetMe` calls Profile.

# Current Design

The internet HTTP gateway both owns browser authentication flows and acts as a
product-data BFF. A second trusted gRPC BFF covers part of the same authenticated
surface. Changes to profile or principal semantics must be duplicated.

# Why This Is a Problem

The two data planes obscure which gateway is authoritative for authenticated
application composition, increase the public gateway's backend reach and attack
surface, and create inconsistent rate-limit/authentication behavior.

# Proposed Design

Keep all three gateway binaries, with explicit scopes:

- `gateway-public`: untrusted browser edge. It owns login/session/OIDC routes,
  HttpOnly session/access cookies, CSRF/CORS, risk, Turnstile, and a thin GraphQL
  transport adapter for authenticated product operations.
- `gateway-services`: authenticated application BFF. It exposes curated,
  domain-intent gRPC services for user/account/profile and organization
  workflows, performs all Authz/Profile composition, and is not a generic
  passthrough for every backend RPC.
- `gateway-internal`: administrative HTTP edge only.

Browser clients continue calling the existing GraphQL origin and never read
bearer tokens from JavaScript. For an authenticated GraphQL request,
gateway-public verifies or mints the short-lived access credential through the
explicit cookie/auth middleware flow, creates a signed delegated principal, and
calls only gateway-services over mTLS. It translates curated BFF responses into
GraphQL models. Direct native/service clients can call gateway-services through
its authenticated gRPC transport.

# Proposed API / Protocol Changes

Replace the single `ServicesGatewayService` with focused services in the same
binary:

```proto
service UserGatewayService {
  rpc GetMe(GetMeRequest) returns (GetMeResponse);
  rpc UpdateMyProfile(UpdateMyProfileRequest) returns (UpdateMyProfileResponse);
  rpc GetPublicProfile(GetPublicProfileRequest) returns (GetPublicProfileResponse);
}

service OrganizationGatewayService {
  rpc CreateOrganization(CreateOrganizationRequest) returns (CreateOrganizationResponse);
  rpc GetOrganization(GetOrganizationRequest) returns (GetOrganizationResponse);
  rpc ListMyOrganizations(ListMyOrganizationsRequest) returns (ListMyOrganizationsResponse);
  rpc ManageMember(ManageMemberRequest) returns (ManageMemberResponse);
}
```

Messages are curated BFF views, not embedded backend persistence messages.
Keep the browser-facing product GraphQL types and operations, but replace their
resolvers/loaders with thin calls to these BFF services. Gateway-public must not
compose, fan out, or call Authz/Profile directly.

`GetMeResponse` contains the exact `MyAccount` view from Authn plus
`profile_state` (`READY`, `PROVISIONING`, `TEMPORARILY_UNAVAILABLE`) and an
optional `MyProfile` only when ready. It follows the account-first failure rules
in `authn-grpc-service-cohesion.md`.

# Dependency / Flow Changes

Current public data flow: `browser -> gateway-public -> Authz/Profile/Authn`.

Target auth flow: `browser -> gateway-public -> Authn`.

Target browser data flow: `browser + HttpOnly cookies + CSRF -> gateway-public
GraphQL adapter -> gateway-services -> Authz/Profile/Authn`.

Target native data flow: `application -> gateway-services ->
Authz/Profile/Authn`. Service identity and delegated-principal verification
apply on every internal hop.

# Security Implications

The public edge loses direct Authz/Profile access and therefore has a smaller
blast radius. Browser mutations remain protected by the public web-security
plan: exact credentialed CORS origins, mandatory CSRF token, Origin validation,
and HttpOnly/Secure cookie invariants. Gateway-services enforces mTLS client
identity, delegated-principal audience, authorization, rate limits, and minimal
response shaping; adapter placement does not itself establish trust.

# Affected Code

- `api/graphql/*.graphqls` and gateway-public generated/resolver/loader code
- `api/proto/gateway/v1/services.proto`
- `internal/gatewaypublic/app/{bootstrap.go,service.go}`
- `internal/gatewayservices/{app,grpc}`
- client documentation, generated code, integration tests, deployment routing

# Implementation Steps

1. Finalize profile and delegated-principal contracts first.
2. Inventory every product GraphQL operation and map it to one curated services
   BFF operation; delete only operations with no live client/product need.
3. Implement focused services in `gateway-services`, including account/profile
   composition and projection-state semantics.
4. Add parallel thin GraphQL adapter resolvers that preserve existing GraphQL
   response names, HttpOnly cookie behavior, CSRF, CORS, and request metadata
   while calling only gateway-services.
5. End-to-end test each query/mutation through browser HTTP, gateway-services,
   and fake/real backends before switching its resolver.
6. Remove gateway-public Authz/Profile clients, composition loaders, and old
   direct resolvers after the last operation migrates.
7. Migrate native clients and remove the broad `ServicesGatewayService`.

# Validation Criteria

- `gateway-public` has no Authz/Profile connection, composition loader, or
  domain implementation; product resolvers only translate GraphQL to the BFF.
- Each authenticated product operation has one domain-composition implementation
  in gateway-services and a minimal response.
- Direct browser auth/OIDC/CSRF/session flows continue to pass.
- Existing browser product operations preserve GraphQL shape and HttpOnly cookie
  handling; mutation requests without valid CSRF/origin fail before BFF calls.
- Wrong-audience/unauthenticated service calls fail before backend work.
- Searches find no duplicate `GetMe`/viewer composition path.
