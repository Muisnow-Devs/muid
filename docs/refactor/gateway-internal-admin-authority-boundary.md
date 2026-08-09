# Internal Gateway Administrator Allowlist Fail-Close

Status: Implemented

Classification: B (immediate security hotfix)

# Problem

The internal gateway's administrator UUID allowlist fails open when configured
as empty or whitespace-only. Any otherwise valid ordinary session JWT can then
reach administrative routes.

# Evidence

- `internal/gatewayinternal/app/config.go` defines `Config.AdminUserIDs` as
  `[]string`.
- `internal/gatewayinternal/app/config_validation.go` checks environment
  presence, not a non-empty semantically valid UUID set.
- `internal/gatewayinternal/app/middleware.go:requireAuth` checks membership only
  when the constructed `admins` map is non-empty.
- `internal/gatewayinternal/app/service.go` applies `requireAuth` to the admin
  route group.
- Existing `internal/gatewayinternal/app/service_test.go` covers a populated
  allowlist but not the empty-list bypass.

# Current Design

`Config.Validate` rejects empty allowlists, invalid or nil UUIDs, and duplicate
canonical UUIDs before infrastructure construction. `requireAuth` parses only
valid non-nil UUIDs and performs an unconditional membership lookup, so an
empty or malformed direct input denies every user.

# Why This Is a Problem

This is a configuration-triggered authorization bypass on administrative
operations. Network placement and bearer verification do not distinguish an
ordinary authenticated user from an administrator.

# Proposed Design

Implemented with semantic validation that applies in debug and production plus
an independent zero-value-denies middleware guard. The decoded `[]string`
configuration shape remains until the later purpose-bound administrator plan
removes this bootstrap mechanism.

This hotfix deliberately preserves the current ordinary-session-plus-allowlist
model. Purpose-bound credentials, TLS, workload identity, and backend authority
are owned by `gateway-internal-admin-authentication-boundary.md` after service
identity is available.

# Proposed API / Protocol Changes

No network protocol changed. `validateAdminUserIDs` supplies startup safety and
the middleware independently fails closed.

# Dependency / Flow Changes

No dependency change. Startup validation precedes infrastructure creation;
middleware performs unconditional membership lookup after JWT verification.

# Security Implications

Finding classification: `Confirmed Vulnerability`.

- Threat: ordinary user performs platform administration.
- Precondition: `ADMIN_USER_IDS` is present but parses empty.
- Boundary: authenticated user to internal administrative HTTP routes.
- Impact: organization/policy and OIDC-client administration.
- Existing protection: bearer verification and optional membership check.
- Insufficiency: empty policy disables authorization.
- Correction: semantic non-empty validation and zero-value deny behavior.

# Affected Code

- `internal/gatewayinternal/app/{config.go,config_validation.go,middleware.go}`
- `internal/gatewayinternal/app/service_test.go`

# Implementation Steps

1. Added trimming, UUID parsing, nil rejection, duplicate detection, and
   non-empty validation in `validateAdminUserIDs`.
2. Invoked config validation before `NewInfra`.
3. Changed `requireAuth` to perform an unconditional UUID-set lookup.
4. Added regression coverage for invalid configuration and empty-policy denial.
5. Kept purpose-bound credentials/backend authority in the separate planned
   record.

# Validation Criteria

- Unsafe values fail startup; an empty direct middleware policy returns 403;
  populated non-admin/admin behavior remains correct.
- `make check`, full Go tests, gateway race tests (152/20), vet, and build passed.
