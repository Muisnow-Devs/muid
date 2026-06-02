# Tests — detailed reference

Read this when writing `Test*` functions, table-driven tests, test helpers, fakes/stubs, fuzz tests, or acceptance tests; when deciding between `t.Error` and `t.Fatal`; when test code involves goroutines.

## Two kinds of helper functions

- **Test helper** — performs setup or cleanup. Failure means *the test environment* is broken (no free port, can't write a file). Calls `t.Helper()` so failure points at the test's call site, not the helper's.
- **Assertion helper** — checks correctness. **Forbidden in idiomatic Go.** Don't write `assertEqual(t, got, want)`. The test function should fail tests directly.

## No assertion libraries

Don't write or use `assert.Equal` / `require.NotNil` / etc.

```go
// Bad:
assert.IsNotNil(t, "obj", obj)
assert.StringEq(t, "obj.Type", obj.Type, "blogPost")
assert.IntEq(t, "obj.Comments", obj.Comments, 2)

// Good:
want := BlogPost{Type: "blogPost", Comments: 2}
if !cmp.Equal(got, want) {
    t.Errorf("AddPost() = %+v, want %+v", got, want)
}
```

For complex types use `cmp.Equal` / `cmp.Diff` from `github.com/google/go-cmp/cmp`. For protobuf messages, pass `protocmp.Transform()`.

```go
// Good:
if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
    t.Errorf("Foo() returned unexpected diff (-want +got):\n%s", diff)
}
```

Don't use `reflect.DeepEqual` for new code (sensitive to unexported fields and implementation details).

## Failure message format

Standard form: **`YourFunc(%v) = %v, want %v`**.

- Name the function that failed (don't rely on the test name alone).
- Print the inputs (or a short description of the case).
- Print **got before want**.
- For diffs, label the order: `(-want +got)` or `(-got +want)` — explicitly.

```go
// Good:
t.Errorf("Reverse(%q) = %q, want %q", input, got, want)
```

## `t.Error` vs `t.Fatal`

Default to `t.Error` / `t.Errorf`: keep going so a single run reports all failures.

Use `t.Fatal` / `t.Fatalf` only when continuing is meaningless:

```go
// Good:
gotMean, gotVar, err := MyDistribution(input)
if err != nil {
    t.Fatalf("MyDistribution(%v) returned unexpected error: %v", input, err)
}
if diff := cmp.Diff(wantMean, gotMean); diff != "" {
    t.Errorf("MyDistribution(%v) mean diff (-want +got):\n%s", input, diff)
}
if diff := cmp.Diff(wantVar, gotVar); diff != "" {
    t.Errorf("MyDistribution(%v) variance diff (-want +got):\n%s", input, diff)
}
```

Common pattern: `t.Fatalf` if encoded ≠ expected (decoding the bad output is meaningless), then `t.Errorf` for subsequent independent checks.

## In table-driven tests

- **Without `t.Run` subtests**: use `t.Error` + `continue` to skip just the broken row.
- **With `t.Run` subtests**: use `t.Fatal` — it skips the current subtest only, not the whole `Test`.

Subtests are preferred — they enable filter (`-run TestX/empty`) and parallel execution.

## NEVER call `t.Fatal` from a non-test goroutine

`t.FailNow`, `t.Fatal`, `t.Fatalf`, `t.SkipNow` may only be called from the goroutine running the test (or the subtest). From spawned goroutines, use `t.Error` / `t.Errorf`.

```go
// Good:
var wg sync.WaitGroup
wg.Add(num)
for i := 0; i < num; i++ {
    go func() {
        defer wg.Done()
        if err := engine.Vroom(); err != nil {
            t.Errorf("vroom: %v", err)  // NOT t.Fatal
            return
        }
    }()
}
wg.Wait()
if seen := engine.NumVrooms(); seen != num {
    t.Errorf("NumVrooms() = %d, want %d", seen, num)  // back on main goroutine
}
```

`t.Parallel()` does **not** make `t.Fatal` safe in extra goroutines.

## Test helpers — when to use `t.Helper()`

Helpers that perform setup and may fail it:

```go
// Good:
func mustAddGameAssets(t *testing.T, dir string) {
    t.Helper()
    if err := os.WriteFile(path.Join(dir, "pak0.pak"), pak0, 0644); err != nil {
        t.Fatalf("Setup failed: could not write pak0: %v", err)
    }
}
```

`t.Helper()` makes the failure line number point at the caller (`mustAddGameAssets(t, dir)`), not at the line inside the helper. Vital when helpers nest or when many tests use them.

If a helper doesn't fail tests, drop `*testing.T` from its signature entirely:

```go
// Good — no t.Helper, no testing.T parameter
func newTestUser() *User { return &User{Name: "alice"} }
```

## Validation logic that's used multiple times

Choose in this order:

1. **Inline it** in the `Test` function, even if repetitive — best in simple cases.
2. **Table-driven test** with the validation in the loop body. Use **named struct fields**:
   ```go
   tests := []struct {
       name  string
       input string
       want  string
   }{
       {name: "empty", input: "", want: ""},
       {name: "single", input: "a", want: "a"},
   }
   for _, tt := range tests {
       t.Run(tt.name, func(t *testing.T) {
           if got := Reverse(tt.input); got != tt.want {
               t.Errorf("Reverse(%q) = %q, want %q", tt.input, got, tt.want)
           }
       })
   }
   ```
   Never positional struct literals: `{"empty", "", ""}` is wrong.
3. **Validation function returning `error`**, used by the `Test` function which then decides how to fail. The validation function does **not** take `*testing.T`.

## `Must*` helpers

For producing a value when there's no good way to handle the error (e.g. a struct field literal in a table):

```go
// Good — test helper:
func mustMarshalAny(t *testing.T, m proto.Message) *anypb.Any {
    t.Helper()
    a, err := anypb.New(m)
    if err != nil {
        t.Fatalf("mustMarshalAny: %v", err)
    }
    return a
}

tests := []struct {
    desc string
    data *anypb.Any
}{
    {desc: "case1", data: mustMarshalAny(t, &mypb.Object{})},
}
```

Don't use `Must*` outside this narrow case (struct fields, package-level vars).

## Acceptance tests

For libraries that expect users to implement an interface (`fs.FS`, `chess.Player`), provide a `<pkg>test` helper package that exercises an arbitrary implementation:

```go
// Good:
package chesstest

func ExerciseGame(t *testing.T, cfg *Config, p chess.Player) error {
    t.Helper()
    // setup...
    // run a whole game with p, return error if invariants broken
}
```

End user:

```go
func TestAcceptance(t *testing.T) {
    if err := chesstest.ExerciseGame(t, chesstest.SimpleGame, deepblue.New()); err != nil {
        t.Errorf("DeepBlue failed acceptance: %v", err)
    }
}
```

The acceptance helper itself follows "keep going" — `t.Fatal` only for setup failure, not for invariant violations (those go into the returned error).

## Use real transports

For component integration tests, use the real client (HTTP, gRPC) connected to a test-double server. Don't hand-roll a mock client — easy to drift from real client behaviour.

Where the service author publishes a testing library, use it.

## Compare semantically, not byte-for-byte

`json.Marshal` may change its output. Don't write `if got != exactJSONString`. Parse the JSON, compare the resulting structure.

For struct returns, do a deep comparison with `cmp` rather than field-by-field manual comparisons.

## Equality with `cmp`

```go
// Good:
if !cmp.Equal(got, want) { t.Errorf("...", got, want) }

// or, for diff-printing:
if diff := cmp.Diff(want, got); diff != "" { t.Errorf("(-want +got):\n%s", diff) }
```

`cmp` may panic on misuse (intentional, to surface bad tests early). It's not for production code.

## Parallel tests

`t.Parallel()` opts the test or subtest into parallelism. When iterating over a table, capture the loop variable:

```go
for _, tt := range tests {
    tt := tt   // capture for the goroutine (Go 1.21 and earlier)
    t.Run(tt.name, func(t *testing.T) {
        t.Parallel()
        // ...
    })
}
```

(Go 1.22+ scopes `for` loop variables per iteration, so the explicit capture is no longer necessary; older codebases still need it.)

## `TestMain` and `sync.Once`

- `TestMain(m *testing.M)` for *whole-process* setup/teardown affecting all tests in the file.
- `sync.Once` for expensive setup shared across multiple tests in the same package, lazily initialized.
- Prefer `t.Cleanup(func)` over `defer` in helpers — runs at test end, plays nicely with subtests.

## Black-box test packages

`*_test.go` files in `package foo_test` (vs `package foo`) test only the exported API. Use this for example tests: file `example_test.go` with `func ExampleX()` shows up in godoc.

## Build tags for integration tests

Integration tests that hit databases / containers / network typically guard with `//go:build integration` and run via `go test -tags=integration`. Project convention; this style guide doesn't mandate the tag name.
