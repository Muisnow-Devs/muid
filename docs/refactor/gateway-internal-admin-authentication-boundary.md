# Internal Gateway Administrator Authentication Boundary

Status: Planned

Classification: S/B (credential, transport, and authority redesign)

# Problem

After the fail-close hotfix, administrator authority still depends on an
ordinary session JWT plus a gateway-local bootstrap list. Internal HTTP does not
require protected transport, and Authn/Authz admin RPC handlers do not
independently authenticate the administrator.

# Evidence

- `internal/gatewayinternal/app/middleware.go:requireAuth` verifies the same
  session-token form used for ordinary authenticated access.
- `internal/gatewayinternal/app/admin.go:outgoingAdminContext` forwards the user
  as raw `x-user-id` metadata.
- `cmd/gateway-internal/main.go` starts an HTTP listener without a required TLS
  configuration contract.
- `internal/authz/grpc/admin_handler.go` and Authn's
  `OIDCClientAdminService` handlers have no common backend administrator
  authentication interceptor.
- `internal/gatewayinternal/app/bootstrap.go` uses insecure gRPC dials, addressed
  by `service-identity-and-principal-propagation.md`.

# Current Design

The gateway alone verifies a bearer and local list. Downstream servers trust its
metadata. A stolen ordinary session for a listed user has no purpose, audience,
recent-authentication, or backend peer binding.

# Why This Is a Problem

Administrative intent and authentication strength are not explicit. Bypassing
the HTTP gateway or compromising its backend channel bypasses the only
administrator check.

# Proposed Design

Require TLS on internal ingress and a short-lived Authn-issued admin access token
with `sub`, `aud=muid-admin`, `auth_time`, `jti`, expiry, and step-up AMR. Token
issuance proves recent authentication but does not embed a durable role. The
gateway asks Authz for an immediate platform-admin decision before dispatch.
Backend admin interceptors verify the authenticated gateway workload and signed
delegated administrator, then independently enforce authority: Authz checks its
local policy; Authn calls Authz's workload-only authorization RPC.

The UUID allowlist becomes an explicitly activated emergency/bootstrap mode and
is disabled by default after durable platform-admin policy is deployed.

# Proposed API / Protocol Changes

- `AdminSessionService.IssueAdminAccessToken` accepts a current reauthentication
  proof and returns the purpose-bound token.
- `AuthorizationService.CheckPlatformAdmin{user_id}` is workload-only and
  returns an allow/deny decision plus policy revision.
- Admin backend calls use `muid-delegated-principal-bin` from the service-identity
  plan; raw `x-user-id` is removed.
- Invalid identity returns `Unauthenticated`; authenticated non-admin authority
  returns `PermissionDenied`/HTTP 403.

# Dependency / Flow Changes

`admin client -> TLS internal gateway -> admin-token verification -> Authz
authority check -> mTLS/delegated backend RPC -> backend authority interceptor ->
handler`.

Authn owns recent authentication/token issuance. Authz owns platform-admin
grants. Gateway owns protocol enforcement, not the role.

# Security Implications

Finding classification: `Defense-in-Depth Improvement` after the confirmed
allowlist bypass is fixed.

The design limits stolen ordinary-session use, gateway bypass, plaintext
observation, and forged admin metadata. Token replay remains bounded by short
expiry and `jti`; revocation-sensitive operations may require a server-side JTI
denylist or one-time token according to threat testing.

# Affected Code

- `cmd/gateway-internal/main.go`
- `internal/gatewayinternal/app/{config.go,middleware.go,admin.go,service.go}`
- Authn admin-token issuance and OIDC admin interceptors
- Authz platform-admin authorization RPC/interceptors
- deployment TLS/identity configuration and integration tests

# Implementation Steps

1. Complete workload identity and delegated-principal propagation.
2. Add recent-authentication proof and admin-token issuance in Authn.
3. Add Authz's workload-only current platform-admin decision.
4. Require TLS for production internal ingress.
5. Enforce authority at gateway, Authz admin server, and Authn admin server.
6. Remove ordinary-session and raw user-metadata admin paths.
7. Disable bootstrap allowlisting by default and document emergency activation.

# Validation Criteria

- Ordinary access/session tokens cannot call any admin route.
- Wrong audience, expired, insufficient-auth-time, altered, and revoked admin
  tokens fail.
- Direct backend calls without allowed workload and delegated admin fail.
- Removing a platform-admin grant takes effect on the next RPC.
- TLS and end-to-end admin authorization tests pass.
