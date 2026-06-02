# Strings and Variables — detailed reference

Read this when concatenating or formatting strings, declaring variables, choosing between `var`, `:=`, `new`, `&T{}`, deciding whether to pre-size a slice/map, or working with channel direction in declarations.

## `:=` vs `var` — initialization form

| Want | Use |
|---|---|
| Initialize with a known non-zero value | `i := 42` |
| Need a zero value, ready for later use | `var coords Point` |
| Need a `*T` to a zero value | `new(T)` or `&T{}` |
| Need a `*T` to a value with fields | `&T{Field: v, ...}` |
| Empty slice (return / accumulator) | `var s []T` |
| Empty map you'll write to | `make(map[K]V)` or `map[K]V{}` (NOT `var m map[K]V` — nil map can be read but not written) |

```go
// Good:
i := 42
var coords Point
var primes []int
buf := new(bytes.Buffer)
msg := new(pb.Message)
c := &Config{Port: 8080}
```

```go
// Bad:
var i = 42                              // use :=
coords := Point{X: 0, Y: 0}             // zero-value: use var
primes := []int(nil)                    // use var
```

Reason: `var x T` reads as "give me a zero-value `T`". `:=` reads as "the value is what's on the right". When the value *is* the zero value, `:=` lies.

## `new(T)` vs `&T{}`

Both produce a `*T` to a zero value, both are correct.

- `new(T)` reads as "I want a zero `T`, by pointer; if I needed to set fields I'd use a constructor or composite literal."
- `&T{}` is more common when fields are filled or when consistency with `&T{Field: v}` is desired.

```go
// Good:
buf := new(bytes.Buffer)         // zero buffer
msg := new(pb.Message)           // zero proto message
c   := &Config{Port: 8080}       // composite literal with fields
```

For protobuf messages: always use the pointer form (`*pb.Bar`). The pointer satisfies `proto.Message`; the value does not. So `var msg = pb.Bar{}` is wrong; use `var msg = new(pb.Bar)` or `&pb.Bar{}`.

## Empty slice — nil vs `[]T{}`

`nil` slice and zero-length slice behave the same for `len`, `cap`, `range`, `append`. Prefer the nil form for empty slices.

```go
// Good:
var t []string
fmt.Println(len(t))   // 0
fmt.Println(cap(t))   // 0
for range t {}        // no-op
t = append(t, "x")    // works

// Bad:
t := []string{}
```

**Don't design APIs that distinguish nil from empty.** Use `len(s) == 0`, never `s == nil`, when checking for emptiness.

```go
// Good:
func describeInts(prefix string, s []int) {
    if len(s) == 0 { return }
    fmt.Println(prefix, s)
}
```

## Composite literals

Use them when you know the initial elements:

```go
// Good:
coords   := Point{X: x, Y: y}
magic    := [4]byte{'I', 'W', 'A', 'D'}
primes   := []int{2, 3, 5, 7, 11}
captains := map[string]string{"Kirk": "James Tiberius", "Picard": "Jean-Luc"}
```

For struct literals from **other packages**, MUST specify field names — positional unsafely couples to field order:

```go
// Good:
r := csv.Reader{Comma: ',', Comment: '#', FieldsPerRecord: 4}

// Bad:
r := csv.Reader{',', '#', 4, false, false, false, false}
```

For **package-local** types, field names are optional but encouraged for non-trivial structs.

Omit zero-value fields when clarity is preserved — they're just noise:

```go
// Bad — most are zero values, the actual changes are buried:
opts := &db.Options{
    BlockSize:            1<<16,
    ErrorIfDBExists:      true,
    BlockRestartInterval: 0,
    Comparer:             nil,
    Compression:          nil,
    // ... 4 more zero fields ...
}

// Good:
opts := &db.Options{
    BlockSize:       1<<16,
    ErrorIfDBExists: true,
}
```

In **table-driven tests**, omit irrelevant zero fields per row — successful test rows omit error-related fields, error rows omit success fields. But include explicit zero values when they're material to understanding the case.

## Size hints / preallocation

```go
// Performance-sensitive, size known:
buf  := make([]byte, 131072)
q    := make([]Node, 0, 16)
seen := make(map[string]bool, shardSize)
```

Use **only** when the code is performance-sensitive AND the size is known.

Most code does not need a size hint. The runtime grows slices and maps automatically.

**Pre-allocating too much wastes memory.** When in doubt, default to zero-init or composite literal. Benchmark before optimising.

## String building — choose by context

| Situation | Use |
|---|---|
| 2–3 short literals or known strings | `+` |
| Formatting with verbs / printf-style | `fmt.Sprintf` |
| Building in a loop / many concatenations | `strings.Builder` |
| Templates with placeholders | `text/template` / `html/template` |
| Mixed bytes and strings, reading via `io.Writer` | `bytes.Buffer` |
| Quoting user-facing strings | `%q` (not manual `"%s"`) |

```go
// Good:
greeting := "hello, " + name

msg := fmt.Sprintf("user %q has %d posts", name, count)

var b strings.Builder
for _, w := range words {
    b.WriteString(w)
    b.WriteByte(' ')
}
result := b.String()
```

`%q` over manually quoting:

```go
// Good:
fmt.Printf("value %q looks like English text", someText)

// Bad:
fmt.Printf("value \"%s\" looks like English text", someText)
fmt.Printf("value '%s' looks like English text", someText)
```

`%q` makes empty strings and control characters visible (`""` reads clearly; `''` doesn't).

## Shadowing — the `:=` trap

`:=` in a nested scope creates a **new** variable, leaving the outer one unchanged.

```go
// Bad:
func handler(ctx context.Context, ...) {
    if shortenDeadlines {
        ctx, cancel := context.WithTimeout(ctx, 3*time.Second)  // new ctx, only inside the if
        defer cancel()
    }
    // here, ctx is the original — the deadline was never applied!
}
```

Fix using `=` (simple assignment) and a separate `var` for the new variable on the right side:

```go
// Good:
func handler(ctx context.Context, ...) {
    if shortenDeadlines {
        var cancel func()
        ctx, cancel = context.WithTimeout(ctx, 3*time.Second)
        defer cancel()
    }
    // ctx now has the shortened deadline if the branch was taken
}
```

Avoid using package names as local variable names — they shadow the package for the rest of the function.

```go
// Bad:
func L() {
    url := "https://example.com/"
    // can't use net/url below
}
```

## `var` blocks

Group related declarations:

```go
// Good:
var (
    pollInterval = flag.Duration("poll_interval", time.Minute, "Interval to use for polling.")
    maxRetries   = flag.Int("max_retries", 3, "Maximum retries.")
)
```

Flags live in their own `var` block, after imports, before any other code.

## Matching brace placement

The closing brace of a multi-line literal sits at the same indentation as the opening line:

```go
// Good:
good := []*Type{
    {Key: "multi"},
    {Key: "line"},
}

// Bad — closing brace cuddled with last value:
bad := []*Type{
    {Key: "multi"},
    {Key: "line"}}
```

For inline literals or proto builders, "cuddled" braces are OK when both sides are also literals:

```go
// Good:
good := []*Type{{ // cuddled
    Field: "value",
}, {
    Field: "value",
}}
```

## `gofmt -s` simplifies redundant types

Repeated type names in slice/map literals are noise:

```go
// Bad:
items := []*Type{
    &Type{A: 42},
    &Type{A: 43},
}

// Good:
items := []*Type{
    {A: 42},
    {A: 43},
}
```

`gofmt -s` (simplify) does this rewrite automatically.

## Integer types

Match the SQL / external schema where applicable:

- `int` → JSON / OpenAPI `integer` (int32-default).
- `int64` → `integer` with `format: int64`.
- `int32` → `integer` with `format: int32`.

For internal use, prefer `int` unless the size is part of the contract.

## Map iteration is unordered

Don't rely on map iteration order. If order matters, sort the keys:

```go
// Good:
keys := make([]string, 0, len(m))
for k := range m {
    keys = append(keys, k)
}
sort.Strings(keys)
for _, k := range keys {
    ...
}
```

## Don't pass pointers to small fixed-size types

`*string`, `*io.Reader`, `*bool`, `*int` parameters are almost always wrong. The pointer is the same size or larger than the value, adds indirection, and forces callers to introduce an addressable variable.

Use pointers for: large structs, structs that may grow, structs containing uncopyable fields (`sync.Mutex`), and protobuf messages.

## Channel direction in variable declarations

Specify direction in function signatures. In local variable declarations, both directions are usually present; let inference handle it. Don't write `var ch <-chan int` for a channel you'll later send on.
