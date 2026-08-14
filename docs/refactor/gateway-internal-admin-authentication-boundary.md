# Internal Gateway Administrator Authentication Boundary

Status: Implemented

Classification: S/B (transport and authority redesign)

# Problem

After the fail-close hotfix, administrator authority still depends on an
ordinary JWT plus a gateway-local UUID allowlist. Internal HTTP does not require
an authenticated workload certificate, and Authn/Authz admin RPCs do not
independently recheck the platform permission.

# Evidence

- `internal/gatewayinternal/app/middleware.go:requireAuth` verifies a JWT and the
  local `AdminUserIDs` list.
- `internal/gatewayinternal/app/admin.go:outgoingAdminContext` forwards raw
  `x-user-id`.
- `cmd/gateway-internal/main.go` has no required TLS/mTLS ingress group.
- `internal/authz/grpc/admin_handler.go` and Authn
  `OIDCClientAdminService` lack a common platform authorization check.
- `internal/gatewayinternal/app/bootstrap.go` uses insecure backend dials.

# Current Design

The gateway-local list is the only administrator grant. Backends trust gateway
metadata, the admin JWT contains no independently checked platform authority,
and there is no cryptographic `admin-ingress` workload boundary.

# Why This Is a Problem

The authorization source is duplicated outside Authz, backend bypass defeats
the sole check, and possessing any listed user's JWT is sufficient regardless
of the calling workload or current platform policy.

# Proposed Design

Gateway Internal serves HTTPS with mandatory client certificates in every mode.
Its ingress TLS group is `MTLS_CLIENT_CA_PATH`, `TLS_CERT_PATH`, and
`TLS_KEY_PATH`; the only recognized client workload is
`spiffe://muid/service/admin-ingress`. The TLS group is parsed at startup,
requires TLS 1.2+, and rejects missing or partial configuration in every mode.
`/healthz` requires valid `admin-ingress` mTLS but no user JWT.
Every `/admin` route requires both that workload and a valid user JWT.

The JWT establishes user identity only and contains no platform roles. Gateway
Internal calls Authz `CheckPlatformPermission` for the route permission, then
uses its `gateway-internal` workload certificate and required `x-user-id` to
call the backend. Authz admin handlers recheck the matching platform permission
locally. Authn OIDC admin handlers call Authz and require both the platform OIDC
permission and the existing organization-scoped permission; neither check can
substitute for the other.

The static Authz policy schema adds:

```yaml
platform_roles:
  platform_admin:
    - platform/policy.read
    - platform/policy.reload
    - platform/oidc_client.read
    - platform/oidc_client.write
platform_bindings:
  "<uuid>": [platform_admin]
```

Unknown roles/permissions, duplicate bindings, malformed/nil user IDs, and
empty role bindings fail policy load. Reload swaps the validated policy
atomically and increments its revision.

# Proposed API / Protocol Changes

```proto
service AuthzService {
  rpc CheckPlatformPermission(CheckPlatformPermissionRequest)
      returns (CheckPlatformPermissionResponse);
}

message CheckPlatformPermissionRequest {
  string user_id = 1;
  string permission = 2;
}

message CheckPlatformPermissionResponse {
  bool allowed = 1;
}
```

The RPC is service-only: allowed workloads are `gateway-internal` and `authn`,
transport user mode is forbidden, and the target user is the explicit validated
request field. Gateway route/RPC permission mapping is:

| Operation | Required permission |
| --- | --- |
| `GET /admin/authz/casbin-rules` / list-rules RPC | `platform/policy.read` |
| `POST /admin/authz/reload-policy` / reload RPC | `platform/policy.reload` |
| `GET /admin/oidc/clients` / list OIDC clients | `platform/oidc_client.read` |
| OIDC client mutations | `platform/oidc_client.write` plus existing organization permission |

Gateway and backend both check the permission for the concrete route/RPC.
Denied platform authority maps to HTTP 403 / gRPC `PermissionDenied`; invalid
workload/JWT/principal maps to the appropriate authentication failure.

# Dependency / Flow Changes

Health flow:

`admin-ingress mTLS -> Gateway Internal /healthz`.

Admin Authz flow:

`admin-ingress mTLS + JWT -> gateway route permission check -> Authz platform
RPC -> gateway-internal mTLS + required user -> AuthzAdmin local permission
recheck -> handler`.

OIDC admin flow:

`admin-ingress mTLS + JWT -> platform permission check -> gateway-internal mTLS
+ required user -> Authn OIDC admin -> Authz platform check + existing org
permission -> handler`.

Authz is authoritative for platform roles/bindings. JWT verification establishes
identity but never administrator authority.

# Security Implications

Finding classification: `Defense-in-Depth Improvement` after the Phase 0
allowlist bypass fix.

This removes gateway-local authorization ownership, prevents unauthenticated
health/admin ingress, binds calls to recognized workloads, and ensures gateway
or backend bypass cannot remove the platform check. OIDC dual authorization
prevents a platform administrator without organization authority—or an
organization administrator without platform authority—from managing clients.

# Affected Code

- `cmd/gateway-internal/main.go`
- `internal/gatewayinternal/app/{config.go,config_validation.go,bootstrap.go,middleware.go,admin.go,service.go}`
- Authz static policy schema/loader, platform authorization RPC/client, and
  AuthzAdmin handlers/interceptors
- Authn OIDC admin interceptors/authorization client
- `api/proto/authz/v1`, generated code, deployment TLS/policy configuration
- end-to-end admin authorization tests and documentation

# Implementation Steps

This record uses the atomic sequence in
`service-identity-and-principal-propagation.md`. Its admin-specific cutover is:

1. Characterize allowlist, JWT, AuthzAdmin, and OIDC organization authorization
   behavior before structural changes.
2. Complete shared strict mTLS, typed principal, and TLS environment groups.
3. Add/validate `platform_roles` and `platform_bindings` with atomic reload.
4. Add `PlatformAuthorizationService.CheckPlatformPermission` and clients.
5. Apply platform checks to Gateway Internal routes and AuthzAdmin RPCs.
6. Apply platform plus existing organization checks to OIDC admin RPCs.
7. Require `admin-ingress` mTLS for health and mTLS+JWT for admin routes.
8. Remove `AdminUserIDs`, allowlist middleware branches, and insecure ingress/
   backend paths in atomic row 13-14 of the service-identity plan.

# Validation Criteria

- Gateway Internal rejects plaintext, unknown/wrong workload certificates,
  missing/multiple URI SANs, TLS below 1.2, and partial production TLS groups.
- `/healthz` succeeds with valid `admin-ingress` mTLS without JWT; admin routes
  additionally reject missing/invalid JWT.
- JWT roles/claims never grant platform authority; changing Authz bindings takes
  effect after atomic policy reload and revision advance.
- Every route and corresponding backend RPC independently denies a missing
  permission.
- OIDC admin succeeds only when both platform and organization permission pass;
  each single-denial combination returns `PermissionDenied`.
- Platform permission RPC rejects caller user metadata, invalid request UUIDs,
  unknown permissions, and workloads other than `gateway-internal`/`authn`.
- Searches find no `AdminUserIDs`, gateway-local admin allowlist, insecure admin
  dial/listener, or backend admin handler lacking policy.
- Coordinated rollout and `make check`, full tests, affected race tests, vet,
  build, generation, and vulnerability scans pass.

# Implemented Result

Gateway Internal now requires a verified `admin-ingress` client certificate for
health and admin traffic, and additionally requires a valid user JWT plus a
live Authz platform permission for every admin route. Its backend calls use the
`gateway-internal` workload certificate. The gateway-local UUID allowlist was
removed. Authz admin RPCs independently recheck their platform permission, and
Authn OIDC administration requires both platform and organization authority.

Tests cover exact ingress workload enforcement (including dynamically selected
TLS configs), JWT outcomes, fail-closed unknown routes, live allow/deny/error
platform decisions, identity forwarding, backend permission rechecks, and both
OIDC authorization dimensions. The affected gateway suite passed under the
race detector before the final repository-wide 919-test pass; stale-path
searches found no `AdminUserIDs`, plaintext admin dial, or local allowlist.
