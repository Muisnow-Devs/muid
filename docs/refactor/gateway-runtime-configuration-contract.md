# Gateway Runtime Configuration Contract

Status: Implemented

Classification: B (startup and operational behavior)

# Problem

Gateway runtime configuration validates environment-variable presence but not
general numeric ranges, cross-field ordering, or all-or-none credential tuples.
Zero and negative values can silently disable enforcement or produce nonsensical
timeouts and thresholds.

# Evidence

- `internal/gatewaypublic/app/config.go`,
  `internal/gatewayservices/app/config.go`, and
  `internal/gatewayinternal/app/config.go` expose ports, request/window
  durations, rate limits, Redis databases, and security thresholds.
- Their `config_validation.go` files primarily check required environment names.
- Public risk configuration has PoW and block thresholds whose ordering is not a
  startup invariant.
- Services mTLS uses client-CA, certificate, and key paths as a three-field tuple
  that can be partially configured.
- Gateway rate limiting and risk tracking receive configuration values whose
  zero/negative semantics are not consistently documented.

# Current Design

All three gateway commands now call `Config.Validate()` after environment decode
and before infrastructure construction. Validators reject invalid ports,
negative Redis databases/rates, nonpositive durations, blank backend/issuer
values, invalid risk ordering, unsafe forwarded-header combinations, and partial
services mTLS tuples. Production additionally requires positive rate limits and
the complete services mTLS tuple.

# Why This Is a Problem

Runtime behavior becomes dependent on constructor defaults and backend edge
cases. Misconfiguration can disable controls, create immediate timeouts, bind an
invalid port, invert risk actions, or leave transport identity half-configured.

# Proposed Design

Implemented per-gateway `Config.Validate() error` methods. They return the first
specific violation and validate:

- ports in 1..65535;
- request, rate-window, CSRF, GeoIP reload, and JWKS cache durations greater
  than zero where configured;
- rate limits nonnegative and greater than zero in production;
- Redis database nonnegative;
- risk scores in the supported range with `pow_threshold < block_threshold`;
- public PoW difficulty in 1..256;
- mTLS CA/cert/key as an all-or-none tuple, and required-all in production where
  the service-identity plan applies;
- issuer/audience and backend address strings non-empty after trimming.

Debug retains the documented zero-rate-limit disable behavior. This record
excludes CSRF/CORS/cookie invariants (public web-security record) and the admin
UUID policy (allowlist fail-close record).

# Proposed API / Protocol Changes

No network protocol change. Runtime constructors accept only validated config;
`LoadConfig` is followed immediately by `Validate` before any external resource
is opened.

# Dependency / Flow Changes

`environment decode -> semantic validation/normalization -> infrastructure
construction -> server construction`. Validation has no network side effects.

# Security Implications

Finding classification: `Defense-in-Depth Improvement`. The contract prevents
silent disabling and partial security setup but does not replace the individual
web/admin/service-identity controls.

# Affected Code

- `internal/gateway{public,services,internal}/app/{config.go,config_validation.go}`
- gateway command bootstrap paths
- `cmd/gateway-{public,services,internal}/main.go`
- `internal/gatewaypublic/app/config_validation_test.go`

# Implementation Steps

1. Added per-gateway semantic validation for addresses, ports, Redis/rate values,
   durations, thresholds, forwarding headers, and mTLS tuples.
2. Enforced `0 < PoW < block <= 100` and public PoW difficulty 1..256.
3. Required all three services mTLS paths together and required them in
   production.
4. Invoked validation before Redis, file, TLS, GeoIP, or gRPC initialization.
5. Added boundary and cross-field regression tests.

# Validation Criteria

- Invalid ports/durations/limits/threshold ordering and partial mTLS tuples fail
  startup with field-specific errors.
- Debug zero-rate-limit behavior remains explicit; production zero is rejected.
- Valid debug/production fixtures pass validation for all three gateways.
- `make check`, full tests, gateway race tests (152/20), vet, and build passed.
