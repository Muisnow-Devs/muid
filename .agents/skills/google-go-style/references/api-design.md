# API Design — detailed reference

Read this when designing exported function signatures, deciding between option struct and variadic options, choosing between value and pointer receivers, sketching interfaces, or wiring dependencies.

## `context.Context` is always first

```go
// Good:
func F(ctx context.Context, /* other args */) error
```

Exceptions (where `ctx` arrives some other way):

- HTTP handler: `req.Context()`.
- gRPC streaming methods: `stream.Context()`.
- Test functions: `t.Context()` (Go 1.24+) or `context.Background()` if older.
- `main` / `init` of a binary: `context.Background()`.

**Never** put a `context.Context` in a struct field. The one exception is when satisfying an external interface that requires it — discuss before doing this.

**Never** create a custom context type or use a non-`context.Context` interface in signatures. Convertibility between every pair of teams' custom contexts is impractical.

## `error` is last

If a function takes `context.Context`, it should usually return `error` so callers can detect cancellation.

## Take interfaces, return concrete types

Consumers define interfaces; they include only the methods they actually use. Producers return concrete types — the caller still has access to fields and methods beyond any interface.

```go
// Good (consumer-side):
package mypkg

type clock interface { Now() time.Time }

func (s *Server) handle(c clock, ...) { ... }
```

```go
// Bad — producer-side oversharing:
package timepkg

type Clock interface { Now() time.Time; Sleep(time.Duration); ... }

func New() Clock { return realClock{} }
```

Exceptions where returning an interface is correct:

- The interface *is* the product (e.g. `error`, `io.Reader` from a constructor).
- Strategy / chaining / factory patterns.
- Encapsulation is the goal.

## Don't create interfaces speculatively

Avoid creating interfaces "for future flexibility". Wait until a real second implementation or test double makes the interface necessary.

- Don't wrap RPC clients in hand-rolled interfaces just to mock them. Use real transports + a fake server.
- Don't define test-double interfaces in production code.

## Function arguments — when to use what

### Positional (default for small APIs)

When the signature has ≤ 3 parameters, all required, all distinct types:

```go
func Parse(input string) (*Config, error)
func WriteTo(w io.Writer, b []byte) (int, error)
```

Keep signatures on a single line — line breaks before an indentation change cause confusion.

### Option struct (last positional argument)

When parameters grow, especially optional ones, or the API needs to evolve over time:

```go
// Good:
type ReplicationOptions struct {
    Config              *replicator.Config
    PrimaryRegions      []string
    ReadonlyRegions     []string
    ReplicateExisting   bool
    OverwritePolicies   bool
    ReplicationInterval time.Duration
    CopyWorkers         int
    HealthWatcher       health.Watcher
}

func EnableReplication(ctx context.Context, opts ReplicationOptions) {
    // ...
}
```

Call site is self-documenting:

```go
storage.EnableReplication(ctx, storage.ReplicationOptions{
    Config:              config,
    PrimaryRegions:      []string{"us-east1"},
    OverwritePolicies:   true,
    ReplicationInterval: time.Hour,
})
```

Benefits:
- Field names + values at the call site (no swapped-argument bugs).
- Irrelevant fields omitted — zero values are fine.
- Per-field documentation reads naturally.
- Adding a field doesn't break callers.

**Never** put `context.Context` in an option struct.

The struct should be exported only if it's used in an exported function.

### Variadic functional options

When most callers pass nothing, or third parties need to define options:

```go
type ReplicationOption func(*replicationOptions)

func ReadonlyCells(cells ...string) ReplicationOption {
    return func(o *replicationOptions) {
        o.readonlyCells = append(o.readonlyCells, cells...)
    }
}

func EnableReplication(ctx context.Context, cfg *Config, primary []string, opts ...ReplicationOption) {
    var o replicationOptions
    for _, opt := range opts { opt(&o) }
    // ...
}
```

Benefits:
- Zero overhead when no options are passed.
- Options can take parameters, can fail, can return errors, can be reused/composed.
- Third parties can define new options if the option function parameter is exported.

Drawbacks:
- A lot of code per option.
- Indirection at the call site.

Use only when the benefits justify the boilerplate.

**Options accept parameters, not presence.** `rpc.FailFast(enable bool)` is preferable to `rpc.EnableFailFast()` — the parameter form lets callers compose options programmatically.

**Last write wins** for non-cumulative options. Document the semantics.

## Avoid output parameters

Don't take `*Out` arguments to write into. Return values instead.

```go
// Bad:
func Compute(in Input, out *Output) error

// Good:
func Compute(in Input) (Output, error)
```

## Channel direction

Specify direction in signatures wherever possible:

```go
// Good:
func sum(values <-chan int) int          // receive-only
func produce(out chan<- int)             // send-only
```

Compiler catches misuse (e.g. accidental `close()` on a receive-only channel from outside the producer).

## Pass values, not pointers, for small fixed-size types

```go
// Bad:
func F(s *string)
func F(r *io.Reader)
```

These types are already small, fixed-size, and pass-by-value is correct. Pointers add indirection without benefit and force callers to materialise an addressable variable.

Exceptions where pointers are correct:
- Large structs or structs that may grow.
- Structs containing fields that **must not be copied** (`sync.Mutex`, `bytes.Buffer`).
- Protobuf messages: always use `*pb.Message`. The pointer satisfies `proto.Message`; the value does not.

## Receiver type — value vs pointer

Pick consistently across all methods of a type. When in doubt, use a pointer receiver.

| Situation | Receiver |
|---|---|
| Method must mutate the receiver | `*T` |
| Receiver contains uncopyable fields (`sync.Mutex`, `bytes.Buffer`) | `*T` |
| Receiver is a "large" struct or array | `*T` |
| Receiver is a slice and method does not reslice/reallocate | `T` |
| Receiver is a map, function, or channel | `T` |
| Receiver is a built-in type or "small" POD struct, no mutation | `T` |
| Want concurrent callers to see modifications | `*T` |
| Future-proofing (don't know how the type will grow) | `*T` |

## Synchronous over asynchronous

Prefer synchronous functions: they finish their work before returning, keep goroutine lifetimes localised, and are easier to test (call → assert).

If callers need concurrency, **they** can spawn a goroutine. Removing unnecessary concurrency from inside a library is much harder than adding it at the caller.

## Goroutine lifetimes must be obvious

```go
// Good:
func (w *Worker) Run(ctx context.Context) error {
    var wg sync.WaitGroup
    for item := range w.q {
        wg.Add(1)
        go func() {
            defer wg.Done()
            process(ctx, item)
        }()
    }
    wg.Wait()  // no goroutine outlives this function
    return nil
}
```

Bad: `go process(item)` with no synchronisation, no ctx, no `wg.Wait`. The goroutine may outlive the program shutdown, leak, or panic on a closed channel.

## No global mutable state

Don't configure libraries via global variables / `init` registration. Pass dependencies as constructor parameters.

```go
// Good:
func New(cfg Config, db *sql.DB, log *log.Logger) *Service { ... }

// Bad:
var DefaultDB *sql.DB
func init() { DefaultDB = ... }
```

Exception: `flag` definitions in `package main`. Library code must not define flags as side effects of importing.

## Generics

Allowed when they earn their complexity. Don't use generics:

- Just because the algorithm is generic over types — if there's only one instantiation in practice, write it for that type.
- To invent DSLs (assertion frameworks, error-handling frameworks).
- When existing language features (slices, maps, interfaces) suffice.

When introducing a generic exported API, document it heavily, including a runnable example.

## Type aliases

`type T1 = T2` is rare. Use it for migrating packages to new locations. Otherwise use a *type definition* `type T1 T2`.

## `flag.Set` in tests is wrong

Override the bound variable directly. `flag.Set` is for parsing the command line.

## Synchronous APIs document cleanup

If your function returns a resource, document the caller's cleanup obligation:

```go
// Good:
// NewTicker returns a new Ticker.
//
// Call Stop to release the Ticker's associated resources when done.
func NewTicker(d Duration) *Ticker
```
