# Atomic Counter Contract

Status: Planned

Classification: S/B (interface cohesion and edge-case semantics)

# Problem

Rate limiting and risk tracking require only an atomic increment-with-first-TTL
operation, but receive broad KV interfaces. Redis and the in-memory mock do not
have a clearly specified, tested common contract for zero/negative TTL, missing
expiry repair, overflow, and concurrency.

# Evidence

- `pkg/shared/kv/interface.go` defines broad `KVStore` and
  `AtomicKVStore`; `IncrementWithTTL` is one method among general get/set/delete
  and compare-delete operations.
- `pkg/gateway/ratelimit/ratelimit.go` and
  `pkg/gateway/risk/tracker.go` depend on `kv.KVStore` but primarily use
  `IncrementWithTTL` for counters.
- `infra/redis/kvstore.go:IncrementWithTTL` implements the operation with Redis
  scripting/commands.
- `infra/mocked/kvstore.go:IncrementWithTTL` independently emulates it and has
  tests for first TTL and self-healing missing expiry.
- Gateway configuration can pass zero/negative limits or windows without one
  documented semantic across implementations.

# Current Design

Callers can access a larger storage surface than necessary. Backend-specific
edge behavior is implicit, so tests against the mock may not prove Redis
production behavior.

# Why This Is a Problem

Rate-limit correctness depends on an atomic window invariant. Divergent expiry
semantics can create never-expiring counters, unexpected resets, disabled
limits, or tests that pass only with the mock.

# Proposed Design

Introduce the minimal `CounterStore` boundary:

```go
type CounterStore interface {
    IncrementWindow(ctx context.Context, key string, window time.Duration) (count int64, err error)
}
```

Contract:

- `window <= 0` returns a stable invalid-window error and does not mutate state;
- the first increment sets expiry atomically;
- a pre-existing counter without expiry is repaired atomically;
- later increments do not extend the window;
- expired keys restart at one;
- integer/type corruption returns a stable storage error;
- implementations are safe under concurrent calls.

Keep the broad KV interface only for consumers that need its full operations.
Rate limiter and risk tracker accept `CounterStore`. Configuration validation,
not the store, decides whether a feature is explicitly disabled.

# Proposed API / Protocol Changes

Internal Go interface change only. Replace `IncrementWithTTL` use with
`IncrementWindow`; stable errors live beside the interface in
`pkg/shared/kv/errors.go` if callers need `errors.Is` behavior.

# Dependency / Flow Changes

Gateway counters depend on a purpose-specific abstraction implemented by Redis
and the mock. PoW and authz-client continue to depend on only the KV operations
they actually need, with smaller interfaces where justified.

# Security Implications

Consistent atomic windows prevent accidental rate-limit bypass and unbounded
counter retention. Input keys remain server-derived; failures continue to use
an explicitly chosen fail-open/fail-closed policy per limiter rather than hidden
storage behavior.

# Affected Code

- `pkg/shared/kv/{interface.go,errors.go}`
- `infra/redis/kvstore.go`, `infra/mocked/kvstore.go`
- `pkg/gateway/ratelimit`, `pkg/gateway/risk`
- gateway bootstrap types and concurrency/contract tests

# Implementation Steps

1. Write backend-independent contract tests for all listed semantics.
2. Add the minimal interface and stable invalid-window/storage errors.
3. Align Redis and mock behavior, including missing-expiry repair and concurrency.
4. Narrow limiter/tracker constructor dependencies.
5. Move feature-disable semantics to validated gateway configuration.
6. Remove obsolete interface methods only when no remaining caller needs them.

# Validation Criteria

- The same contract suite passes for mock and a real Redis integration fixture.
- Concurrent increments produce a contiguous count and one non-sliding expiry.
- Nonpositive windows do not mutate data and return the same classified error.
- Limiter/risk tests pass with `-race`.
- No gateway counter caller depends on the broad KV interface.
