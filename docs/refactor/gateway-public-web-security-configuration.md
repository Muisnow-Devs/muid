# Public Gateway Web Security Configuration

Status: Implemented

Classification: B (security behavior)

# Problem

Production-required browser security settings are checked for environment
presence but not semantic safety. Empty CSRF material disables enforcement,
credentialed wildcard CORS is representable, the default CORS headers omit the
CSRF header, and cookie prefix/domain/security invariants are not validated.

# Evidence

- `internal/gatewaypublic/app/config_validation.go` lists
  `GATEWAY_PUBLIC_CSRF_SECRET` but does not require a non-empty strong value.
- `internal/gatewaypublic/app/bootstrap.go` constructs `csrf.Manager` only when
  `strings.TrimSpace(cfg.CSRFSecret) != ""`.
- `internal/gatewaypublic/app/service.go:csrfProtect` becomes a no-op when the
  manager is nil.
- `internal/gatewaypublic/app/service.go` enables
  `httpx.CORS` with credentials for configured origins and separately uses
  `requireAllowedOrigin` for the CSRF-exempt access-token endpoint.
- `pkg/gateway/httpx/middleware.go:CORS` accepts wildcard entries.
- `internal/gatewaypublic/app/config.go` independently exposes session/access
  cookie name, domain, Secure, and SameSite fields.
- GraphQL tests send `X-CSRF-Token`, while the configured CORS allowed-header
  defaults do not establish that header as an invariant.

# Current Design

`Config.Validate` now applies semantic safety checks before `NewInfra`.
Production requires a CSRF secret of at least 32 bytes, Turnstile and persisted
operation configuration, normalized HTTPS origins, and secure cookies. Debug
permits only explicit local-development relaxations such as HTTP loopback
origins and an absent CSRF manager.

# Why This Is a Problem

CSRF protection and credentialed origin isolation must never depend on an empty
string convention in production. Invalid `__Host-`/`__Secure-` cookie settings
can be ignored by browsers, and missing preflight headers can make the secure
mutation flow unusable.

# Proposed Design

Implemented direct `Config.Validate()` checks. Production requires:

- a non-empty random CSRF secret of at least 32 bytes;
- explicit normalized HTTPS origins, with no `*`, path, query, fragment, or
  opaque origin;
- `X-CSRF-Token`, `Content-Type`, and `Authorization` in the CORS allowed-header
  set;
- `Secure=true` for all authentication cookies;
- `__Host-` cookies with no Domain and Path `/`;
- `__Secure-` cookies with Secure enabled;
- `SameSite=None` only with Secure.

Origins reject wildcards, user info, paths, queries, fragments, invalid ports,
duplicates, surrounding whitespace, and non-normalized forms. Production
accepts HTTPS only; debug additionally accepts HTTP loopback. The access-token
endpoint uses the validated exact-origin list.

# Proposed API / Protocol Changes

No protobuf change. Existing config fields are retained and validated together
before infrastructure construction.

# Dependency / Flow Changes

Configuration is parsed before any listener or backend connection starts.
Middleware receives validated values and cannot represent a production-disabled
CSRF manager or wildcard credentialed origin.

# Security Implications

Finding classification: `Architectural Security Risk`.

- Threat: cross-site state changes, origin-policy bypass, or insecure bearer
  cookie handling.
- Precondition: unsafe production configuration or wildcard origin.
- Boundary: untrusted browser/internet to `gateway-public`.
- Impact: authenticated mutations or token issuance in a victim's browser.
- Existing protection: CSRF HMAC tokens, origin matching, HttpOnly cookies.
- Insufficiency: those controls can be silently disabled or inconsistently
  configured.

# Affected Code

- `internal/gatewaypublic/app/{config.go,config_validation.go,bootstrap.go,service.go}`
- `internal/gatewaypublic/app/{config_validation_test.go,service_test.go}`

# Implementation Steps

1. Added semantic validation and table-driven configuration tests.
2. Rejected unsafe production CSRF, origin, Turnstile, persisted-operation, and
   cookie combinations before infrastructure opens.
3. Made a non-nil CSRF manager an invariant of valid production startup.
4. Reused the validated exact-origin values for CORS and access-token checks.
5. Added `X-CSRF-Token` to credentialed preflight policy.

# Validation Criteria

- Production startup rejects empty/short CSRF secrets, wildcard or malformed
  origins, insecure cookies, and invalid prefix/domain combinations.
- Valid preflight requests including `X-CSRF-Token` succeed only for allowlisted
  origins and set one exact `Access-Control-Allow-Origin` value.
- Cross-origin mutation/access-token requests from other origins fail.
- Existing CSRF token tampering/expiry and gateway browser-security tests pass.
- `make check`, full tests, gateway race tests (152/20), vet, and build passed.
