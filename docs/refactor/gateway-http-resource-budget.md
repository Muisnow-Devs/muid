# Gateway HTTP Resource Budget

Status: Implemented

Classification: B (availability and request-processing behavior)

# Problem

Public and internal HTTP gateways do not apply a complete, explicit per-request
resource budget. Body/header size and connection timeouts are incomplete, the
configured request timeout is unused on HTTP handlers, and expensive credential
verification can occur before abuse limiting.

# Evidence

- `pkg/gateway/httpx/server.go:Config` has `ReadHeaderTimeout` and
  `ShutdownTimeout`, but no read, write, idle, maximum-header, or request-body
  limits.
- `internal/gatewaypublic/app/config.go` and
  `internal/gatewayinternal/app/config.go` define `RequestTimeoutSeconds`.
- Their HTTP service construction does not apply that value to handler
  execution.
- `internal/gatewayinternal/app/service.go` orders `requireAuth` before its
  authenticated rate-limiter; comparable paths in the public gateway resolve
  credentials before caller-specific limits.
- GraphQL complexity is capped and persisted operations exist, but HTTP bodies
  are not bounded before decoding.

# Current Design

`httpx.Server` now bounds complete reads, headers, writes, idle connections,
header bytes, request execution, and shutdown. Public/internal application
routes run through an asynchronous `httpx.Budget`; liveness `/healthz` bypasses
the budget and Redis/risk dependencies.

# Why This Is a Problem

Availability controls must cover the unauthenticated portion of a request.
Otherwise an attacker can exhaust memory, connections, CPU, or backend calls
before authenticated policies apply.

# Proposed Design

Implemented `httpx.Config` connection limits and `httpx.Budget`. Budget buffers
up to 1 MiB request bodies and responses, propagates a request deadline, and
admits at most 256 handler goroutines, including handlers still running after a
client receives a timeout. Saturation returns 503 without starting work;
deadline expiry returns 504 and suppresses late writes. A panic before the
deadline is re-panicked to outer recovery; a late panic is logged once with
trace context and panic type but never its value.

# Proposed API / Protocol Changes

- Extended `httpx.Config` with read/write/idle/request timeouts and maximum
  header bytes.
- Added `httpx.Budget(BudgetConfig)` with request timeout, maximum body bytes,
  and maximum concurrency; `DefaultMaxConcurrentRequests` is 256.
- `gateway-runtime-configuration-contract.md` exclusively owns numeric range,
  cross-field, and explicit-disable validation for these fields.

# Dependency / Flow Changes

`outer trace/log/recovery/security/CORS -> health bypass or application budget ->
existing abuse/auth middleware -> handler -> deadline-aware gRPC`.

Because Budget is outside application authentication/risk work, invalid
credentials also consume the same bounded 256-slot execution budget without a
separate pre-auth limiter.

# Security Implications

Finding classification: `Defense-in-Depth Improvement`.

The change reduces slow-client, oversized-request, invalid-token CPU, and
unbounded-handler denial-of-service risk. It does not replace infrastructure
load balancing or global volumetric protection.

# Affected Code

- `pkg/gateway/httpx/{server.go,budget.go,budget_test.go}`
- `internal/gatewaypublic/app/{app.go,service.go,service_test.go}`
- `internal/gatewayinternal/app/{app.go,service.go,service_test.go}`

# Implementation Steps

1. Completed runtime validation for configured request timeouts.
2. Extended `httpx.Server` with bounded connection/header behavior and forced
   shutdown fallback.
3. Added buffered body/response handling, deadlines, and the 256-slot admission
   semaphore in `Budget`.
4. Placed cheap observability/recovery/security middleware outside Budget and
   excluded health checks from application admission.
5. Added timeout/overload/oversize/late-write/panic/concurrency tests.

# Validation Criteria

- Oversized bodies return 413; timed-out work returns 504; saturated admission
  returns 503; late responses cannot overwrite the transmitted result.
- Health remains available while all 256 application slots are occupied.
- Outer logging/recovery/security middleware observes budget responses; late
  panic logging is traceable and does not expose the panic value.
- `make check`, full tests, gateway race tests (152/20), vet, and build passed.
