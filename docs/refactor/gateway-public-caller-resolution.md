# Public Gateway Caller Resolution

Status: Planned

Classification: S (make side effects explicit)

# Problem

The public GraphQL helper named `authed` appears to resolve caller identity but
can mint an access token through Authn and set a response cookie. Seventeen
resolvers call it, so a product resolver can perform hidden network and
response-mutation side effects before delegating work.

# Evidence

- `internal/gatewaypublic/graph/resolver.go:authed` resolves caller identity from
  cookies/tokens and can call access-token issuance before returning outgoing
  metadata.
- `internal/gatewaypublic/graph/data.resolvers.go` calls `r.authed(ctx)` in 17
  query/mutation paths.
- `internal/gatewaypublic/graph/resolver.go` also owns cookie reads/writes,
  Profile mapping, Authz mapping, and loaders in a file over 700 lines.
- `internal/gatewaypublic/app/data_test.go:TestDataPlaneMintsAccessTokenFromSessionCookie`
  confirms that an authenticated data operation can mint and set an access-token
  cookie.

# Current Design

Resolvers request an authenticated context through one convenience method. That
method chooses between an access-token cookie and an opaque session cookie and
may perform token issuance as an incidental fallback.

# Why This Is a Problem

The primary control flow hides a security-sensitive network call and response
mutation behind a vague authentication lookup. It complicates caching/retry
reasoning and lets queries change credentials without naming that behavior.

# Proposed Design

As the GraphQL implementation becomes a thin gateway-services adapter, separate
pure caller resolution from explicit credential bootstrap:

- A named `BrowserAccessMiddleware` verifies the access-token cookie once. When
  it is absent but a session cookie exists, the middleware—not a resolver—calls
  `SessionService.IssueAccessToken`, sets the HttpOnly access cookie, verifies
  the result, and stores an immutable typed caller in request context.
- `requireCaller(ctx)` only returns that caller or an unauthenticated error; it
  performs no RPC, persistence, or response mutation.
- The explicit access-token endpoint uses the same middleware-owned exchange
  component; resolvers never call it.
- `outgoingPrincipal(ctx, caller)` attaches the already-issued signed delegated
  principal only to gateway-services calls.

Split resolver files by schema responsibility only where that reduces
cognitive load; do not introduce pass-through use-case/helper layers.

# Proposed API / Protocol Changes

No product GraphQL change is required. The retained thin adapter's resolver
dependency is a pure `CallerProvider` established by middleware, plus focused
gateway-services clients. Cookie exchange is an explicit HTTP middleware
responsibility with CSRF/origin policy inherited from the route.

# Dependency / Flow Changes

Credential flow: `BrowserAccessMiddleware -> existing access-cookie verify`, or
`session-cookie verify/exchange -> Authn IssueAccessToken -> HttpOnly Set-Cookie
-> typed caller`.

Data flow: `typed caller -> thin GraphQL resolver -> signed delegation ->
gateway-services BFF`. No resolver invokes the credential flow.

# Security Implications

This is a clarity and defense-in-depth improvement. Credential mutation is
auditable at the HTTP boundary, CSRF/origin rules remain explicit, and resolver
retry cannot independently rotate/mint credentials. HttpOnly cookies remain the
browser credential boundary and are never exposed in GraphQL responses.

# Affected Code

- `internal/gatewaypublic/graph/{resolver.go,data.resolvers.go}`
- `internal/gatewaypublic/app/{service.go,data_test.go}`
- `internal/gatewaypublic/reqctx`
- GraphQL schema/generated output if the data plane is removed

# Implementation Steps

1. Complete the gateway-boundary and Authn focused-service prerequisites.
2. Add `BrowserAccessMiddleware` and its single request-scoped exchange state.
3. Introduce typed caller context and reuse the same exchange component at the
   explicit access-token endpoint.
4. Replace every resolver use with pure `requireCaller` and focused
   gateway-services calls.
5. Split mapping/loader/cookie responsibilities into domain-named files without
   adding forwarding layers.
6. Delete `authed` and tests that expect hidden minting; add no-side-effect tests.

# Validation Criteria

- Resolver execution cannot cause Authn access-token issuance or `Set-Cookie`;
  any one-time request bootstrap happens before GraphQL execution in named
  middleware.
- Only `BrowserAccessMiddleware` and the explicit token endpoint use the shared
  credential exchange component.
- Caller resolution performs no network call and is evaluated once per request.
- Search finds no `authed` symbol and no token issuance from data resolvers.
- End-to-end browser tests prove HttpOnly cookies, CSRF/origin rejection, caller
  context, and gateway-services delegation across query and mutation routes.
