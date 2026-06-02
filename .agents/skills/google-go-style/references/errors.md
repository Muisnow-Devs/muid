# Errors — detailed reference

Read this when handling, wrapping, returning, or designing errors in Go: choosing `%v` vs `%w`, sentinel placement, RPC-boundary errors, structured errors, `errors.Is` / `errors.As`.

## Core principles

- `error` is the **last** return value.
- Exported functions returning errors return the `error` interface, never a concrete pointer type. A nil concrete pointer wrapped in an interface is non-nil — silent bug.
- A function taking `context.Context` should usually return `error` so the caller can detect cancellation.
- Returning a non-nil error means **all other return values are unspecified** (typically zero values, but don't rely on it).
- Don't ignore errors with `_` unless documented to never fail (e.g. `(*bytes.Buffer).Write`); add a comment explaining why.

## Error string format

Lowercase, no trailing punctuation, no `\n`, no capitalization unless starting with a proper noun, exported name, or acronym.

```go
// Good:
err := fmt.Errorf("something bad happened")

// Bad:
err := fmt.Errorf("Something bad happened.")
```

Reason: errors are usually embedded in larger messages. Capital letters and trailing periods make composed strings ugly.

The full *displayed* message (logs, UI, test failures) is a different stratum — that one is capitalized and punctuated:

```go
// Good:
log.Errorf("Operation aborted: %v", err)
t.Errorf("Op(%q) failed unexpectedly; err=%v", args, err)
```

## In-band errors are forbidden

Returning `-1` / `""` / `nil` to signal "no value" is unsafe — callers forget to check, and the bad value flows into the next call.

```go
// Bad:
func Lookup(key string) int  // returns -1 on missing

// Good:
func Lookup(key string) (value string, ok bool)
```

## `%v` vs `%w` — when to wrap

`%w` produces a chained error (`Unwrap() error` chain, inspectable with `errors.Is` / `errors.As`).
`%v` produces a flat string-formatted error (chain semantics dropped).

**Use `%w` when:**
- Callers (in your codebase) need `errors.Is(err, ErrSomething)` or `errors.As(err, &target)`.
- Your package's API documents and tests that the underlying error remains inspectable.

**Use `%v` when:**
- The error is for human display (logs, UI) and no programmatic inspection is needed.
- You're at an external boundary (RPC, IPC, storage) translating internal errors into a canonical error space — clients want a `codes.Internal`, not your filesystem error.
- You're creating a fresh, semantically different error and intentionally hiding the underlying cause.

```go
// Good — internal helper, caller may errors.Is(err, fs.ErrNotExist):
return fmt.Errorf("couldn't find remote file: %w", err)

// Good — at the gRPC boundary, translate to canonical:
return nil, status.Errorf(codes.Internal, "couldn't find fortune database")
```

## Placement of `%w`: end (default) vs start (sentinel)

The chain is built newest→oldest regardless of placement. **Where you put `%w` in the format string** decides whether the printed text matches the chain order.

**Default — `%w` at the end** (so printed order matches chain order, `outer: middle: inner`):

```go
// Good:
err1 := fmt.Errorf("err1")
err2 := fmt.Errorf("err2: %w", err1)
err3 := fmt.Errorf("err3: %w", err2)
fmt.Println(err3) // err3: err2: err1
```

**Exception — wrapping a sentinel for categorisation, `%w` at the start:**

```go
// Good:
package parser

var ErrParse = fmt.Errorf("parse error")
var ErrParseInvalidHeader = fmt.Errorf("%w: invalid header", ErrParse)

func parseHeader() error {
    return fmt.Errorf("%w: invalid character: %v", ErrParseInvalidHeader, err)
}
```

Reason: an observer (or grep, or a log scraper) can identify the *category* of failure at a glance — "parse error: invalid header: …". The sentinel is the most informative thing about the error; it should be first.

**Bad — `%w` in the middle** (printed order doesn't match chain in either direction):

```go
// Bad:
err2 := fmt.Errorf("err2-1 %w err2-2", err1)
```

## Don't add redundant context

The wrapped error already carries some info. Adding a duplicate annotation makes the printed chain repeat itself.

```go
// Good:
if err := os.Open("settings.txt"); err != nil {
    return fmt.Errorf("launch codes unavailable: %v", err)
    // launch codes unavailable: open settings.txt: no such file or directory
}

// Bad:
if err := os.Open("settings.txt"); err != nil {
    return fmt.Errorf("could not open settings.txt: %v", err)
    // could not open settings.txt: open settings.txt: no such file or directory
}
```

Don't wrap purely to mark "something failed" — the error's existence already says that:

```go
// Bad:
return fmt.Errorf("failed: %v", err)  // just `return err`
```

## Sentinel errors

Package-level `errors.New` values that callers compare against.

```go
// Good:
package os

var (
    ErrInvalid = errors.New("invalid argument")
    ErrPermission = errors.New("permission denied")
)
```

Naming: `ErrFoo` (exported) or `errFoo` (unexported). Document significant sentinels in the function's doc comment.

Compare with `errors.Is`, never with `==` if anyone might wrap them:

```go
// Good:
if errors.Is(err, fs.ErrNotExist) { ... }
```

## Structured (typed) errors

When callers need fields, not just identity:

```go
// Good:
type SyntaxError struct {
    Line int
    Msg  string
}

func (e *SyntaxError) Error() string { ... }
```

Document whether the receiver is a pointer (`return type *SyntaxError`-style). Critical for `errors.As` and `cmp` to work.

```go
// Good:
// If there is an error, it will be of type *PathError.
func Chdir(dir string) error
```

(Function declares return type `error`, not `*PathError`, because of the [nil-interface trap](https://go.dev/doc/faq#nil_error).)

## Don't pattern-match error strings

```go
// Bad:
if regexp.MatchString(`duplicate`, err.Error()) { ... }
```

If you need to distinguish, use sentinels (`errors.Is`) or types (`errors.As`).

## Don't log AND return the same error

Pick one. Logging at every layer + returning it produces N copies of the same error in the logs.

The caller is usually better positioned to decide whether to log, suppress, rate-limit, or retry.

## RPC / process boundaries — use canonical codes

At the edge where errors leave the process (gRPC, HTTP API), translate to a canonical error space rather than wrapping internal errors raw with `%w`. The client doesn't care about your filesystem error type; they care that this was `Internal` / `NotFound` / `PermissionDenied` / `InvalidArgument`.

```go
// Good:
import (
    "google.golang.org/grpc/codes"
    "google.golang.org/grpc/status"
)

return nil, status.Errorf(codes.NotFound, "fortune database missing")
```

## `errors.Is` vs `errors.As`

- `errors.Is(err, target)` — does the chain contain a sentinel/value equal to `target`? (Identity comparison via `Is(error) bool` if defined, else `==`.)
- `errors.As(err, &target)` — is there a value in the chain assignable to `*target`? Used to extract typed fields.

```go
// Good:
if errors.Is(err, ErrTimeout) { retry() }

var pathErr *fs.PathError
if errors.As(err, &pathErr) { log.Printf("path: %s", pathErr.Path) }
```

## `errgroup` for "first error wins"

When orchestrating concurrent operations and only the first failure matters, `golang.org/x/sync/errgroup` is the idiomatic abstraction.

## Documenting errors

Document significant sentinels and error types your function returns:

```go
// Good:
// Read reads up to len(b) bytes from the File and stores them in b. It returns
// the number of bytes read and any error encountered.
//
// At end of file, Read returns 0, io.EOF.
func (*File) Read(b []byte) (n int, err error)
```

If the *whole package* uses an error convention, document it on the package itself (`// Package os ...`).
