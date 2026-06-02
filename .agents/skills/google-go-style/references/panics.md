# Panics — detailed reference

Read this when deciding between `panic`, `log.Fatal`, `log.Exit`, and `error` return; when wrapping a parser with `recover`; when porting code that uses panic-as-control-flow.

## Default: don't panic

Use `error` and multiple return values for *any* failure a caller can plausibly handle. Panic has three legitimate uses (below). Everything else returns an error.

## Where panic is acceptable

### 1. Invariant violations / "impossible" states

Conditions that should always be caught in tests / code review and indicate a bug:

```go
// Good:
switch i {
case 42:
    return "yup"
default:
    log.Fatalf("invalid input: %d", i)
    panic("unreachable")
}
```

The `panic("unreachable")` exists only because the compiler doesn't know `log.Fatalf` is terminal.

In a *library*, prefer `log.Fatal` or returning an error. `panic` for invariants is OK at the API boundary if it's documented (e.g. the standard library's `reflect` panics on misuse).

### 2. Internal parser-style code with a guaranteed `recover` at the boundary

Deep recursion plumbing errors through every return value can drown the algorithm in noise. Use a private panic type internally + a top-level `defer recover` that converts back to `error`:

```go
// Good:
type syntaxError struct{ msg string }

func parseInt(in string) int {
    n, err := strconv.Atoi(in)
    if err != nil {
        panic(&syntaxError{"not a valid integer"})
    }
    return n
}

func Parse(in string) (_ *Node, err error) {
    defer func() {
        if p := recover(); p != nil {
            sErr, ok := p.(*syntaxError)
            if !ok {
                panic(p)  // not ours — re-panic
            }
            err = fmt.Errorf("syntax error: %v", sErr.msg)
        }
    }()
    // ...
}
```

**The panic type must be private to the package.** It must NEVER cross a package boundary as a panic. Always re-panic if `recover` returns something you don't recognise.

Manage resources carefully — `defer recover` does not magically run other cleanups in the unwound call frames.

### 3. Package-level `Must*` initialisers

When you need a value at package init time and the operation can fail, panic is acceptable because there's no error-return mechanism for `var` declarations:

```go
// Good:
var DefaultVersion = MustParse("1.2.3")

func MustParse(version string) *Version {
    v, err := Parse(version)
    if err != nil {
        panic(fmt.Sprintf("MustParse(%q) = _, %v", version, err))
    }
    return v
}
```

Standard library examples: `template.Must`, `regexp.MustCompile`.

`Must*` is **not** for runtime user input. It's for constants known at compile time.

`Must*` is also acceptable in **tests** (where the panic / `t.Fatal` aborts a single test, not the program). Test helpers should call `t.Fatal`, not raw panic, because they have a `*testing.T`.

## Where panic is forbidden

- **HTTP / RPC handlers.** Don't panic; return an error. `net/http`'s default recover for handler panics is widely considered a historical mistake — don't rely on it; do not write servers that depend on it.
- **Across public API boundaries.** A library function should never let a panic escape unless it's the established contract (e.g. `reflect`).
- **As an alternative to `error`.** `panic("input was nil")` in a normal function is wrong; return an error.
- **As "defensive" recovery.** Don't `recover()` to mask crashes ("at least the server stays up"). Corrupted state propagates further; bugs become harder to diagnose. Crash, restart, fix.

## `log.Fatal` vs `log.Exit` vs `panic`

Google's `log` package (or `github.com/golang/glog`):

- **`log.Fatal*`** — log + stack trace + `os.Exit(1)`. Deferreds DO NOT run. Use for *invariant violations* where a stack trace helps diagnose.
- **`log.Exit*`** — log + `os.Exit(1)`, no stack trace. Deferreds DO NOT run. Use for *expected user-facing failures* in `main` (bad config, missing flag) where a stack trace is noise and a human-readable message is what matters.
- **`panic`** — generates a stack trace, runs deferred functions, can be `recover`'d. Less reliable than `log.Fatal` for terminal conditions because deferred code may deadlock or further corrupt state.

Standard library's `log.Fatal` is **not** what's referenced here — that one is `os.Exit(1)` with a regular log line. The Google variant is more powerful (and the one this skill describes when "log.Fatal" is mentioned).

## Where to terminate the program

| Where | Use |
|---|---|
| `main` — bad flag/config | `log.Exit` (no stack) |
| `main` — caught an unrecoverable error | `log.Exit` |
| `main` / `init` — invariant violation | `log.Fatal` |
| Library — invariant that should never happen | `error` return *or* `log.Fatal` |
| Library — runtime error caller might handle | `error` return |
| `init` function — operation must succeed for package to be usable | `panic` (acceptable; cannot return error) |
| Inside a `Must*` package-level initializer | `panic` |
| HTTP / RPC handler — anything | return `error`, never panic, never `log.Fatal` |

## Don't recover to be defensive

```go
// Bad:
defer func() {
    if r := recover(); r != nil {
        log.Printf("recovered: %v", r)
        // continue serving requests on corrupted state
    }
}()
```

The further from the panic, the less you know about state — locks may be held, files half-written, caches inconsistent. The disciplined approach: monitoring, alerting, fix bugs, let the process crash and restart cleanly.

## Don't `log` before flags are parsed

In `init` or a `Must*` function called at package init, you can't reliably call `log.*` (logging may not be configured). Use raw `panic` instead.
