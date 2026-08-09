# Gateway Lifecycle Ownership

Status: Implemented

Classification: S then B (structural ownership, then bounded shutdown behavior)

# Problem

Gateway startup and shutdown ownership is split between command entry points,
`App`, and server wrappers. Both `Start` and `main` participate in stopping
resources, shutdown may execute twice, serve failures do not have one cleanup
path, and gRPC graceful stop has no deadline.

# Evidence

- `cmd/gateway-public/main.go`, `cmd/gateway-internal/main.go`, and
  `cmd/gateway-services/main.go` run gateway startup and then call
  `gateway.Stop()`.
- `internal/gatewaypublic/app/app.go`,
  `internal/gatewayinternal/app/app.go`, and
  `internal/gatewayservices/app/app.go` also expose `Stop` and wrap server plus
  infrastructure cleanup.
- `pkg/gateway/httpx/server.go:Start` waits for context cancellation and calls
  `Stop` internally.
- `internal/gatewayservices/app/service.go` calls `GracefulStop` both from its
  serving path and public `Stop`; `GracefulStop` is unbounded.
- Infrastructure dependencies include gRPC connections, Redis, and GeoIP
  resources whose close order is distributed across bootstrap/app code.

# Current Design

Each command now loads and validates config, constructs infrastructure/app, and
calls `App.Run(ctx)` directly. `App.Run` owns serving and defers infrastructure
close. HTTP and services gRPC servers each own cancellation/serve-error handling
and bounded draining.

# Why This Is a Problem

Competing shutdown paths create close races, double shutdown, ambiguous errors,
and leaks on partial startup or early serve failure. An unbounded graceful gRPC
drain can prevent process termination indefinitely.

# Proposed Design

Implemented `App.Run(ctx) error` as the single production owner. Partial
bootstrap paths close resources directly; `NewApp` failure is closed by the
command before ownership transfer. `httpx.Server.Run` drains with a timeout and
forces connection close on expiry. Services gRPC attempts `GracefulStop` and
calls `Stop` after a deadline of at least 15 seconds and at least request timeout
plus five seconds. Public GeoIP watching is idempotent, context-cancelable, and
`Close` joins its watcher before closing the active database.

# Proposed API / Protocol Changes

- Replace `Start(ctx)` plus caller-owned `Stop()` with `Run(ctx) error` for all
  three gateway apps.
- Add bounded HTTP and gRPC drain helpers within their server owners.
- No network protocol change.

# Dependency / Flow Changes

`main -> BuildApp -> App.Run -> serve -> cancellation/error -> bounded drain ->
close dependencies -> return`.

# Security Implications

Reliable shutdown reduces stale listeners and incomplete credential/key/GeoIP
resource cleanup. Forced-stop timeout must be long enough for normal requests
but bounded against malicious or stuck clients.

# Affected Code

- `cmd/gateway-{public,services,internal}/main.go`
- `internal/gateway{public,services,internal}/app/{app.go,bootstrap.go,service.go}`
- `pkg/gateway/httpx/server.go`
- `infra/geoip/{interface.go,maxmind.go,maxmind_test.go}`
- lifecycle and race tests

# Implementation Steps

1. Added `Run` orchestration to all gateway apps and commands.
2. Removed duplicate command-owned stopping and transferred infrastructure
   closure to `App.Run` after successful app construction.
3. Added bounded HTTP drain/forced close and bounded gRPC graceful/forced stop.
4. Made GeoIP background watching joinable and close-safe under reload races.
5. Added cancellation, forced-drain, watcher-close, and race coverage.
6. Removed obsolete production `Start`/`Stop` call patterns.

# Validation Criteria

- Successful and failed construction paths close owned infrastructure; GeoIP
  close cancels and joins the watcher exactly once.
- HTTP cancellation/serve failure drains once; stuck gRPC requests are forcibly
  stopped after the bounded deadline.
- `make check`, full tests, gateway race tests (152/20), vet, and build passed.
