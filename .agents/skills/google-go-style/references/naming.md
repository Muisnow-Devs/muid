# Naming — detailed reference

Read this when naming functions, methods, types, receivers, packages, test doubles, or local variables; when renaming for clarity; when picking proto-import aliases.

## Functions and methods

- **No `Get` / `get` prefix on getters.** `User()`, not `GetUser()`. Exception: HTTP GET or any concept where "get" is part of the domain.
- **Verbs for actions, nouns for accessors.**
- **Don't repeat the package name** in identifiers. `widget.New`, not `widget.NewWidget`. `db.Load`, not `db.LoadFromDatabase`.
- **Don't repeat the receiver type** in method names: `(c *Config).WriteTo`, not `(c *Config).WriteConfigTo`.
- **Don't repeat parameter names**: `func Override(dest, source *Config)`, not `func OverrideFirstWithSecond(dest, source *Config)`.
- **Don't repeat return types**: `func Transform(input *Config) *jsonconfig.Config`, not `func TransformToJSON(input *Config) *jsonconfig.Config`.
- **Type-specific variants append the type suffix**: `ParseInt`, `ParseInt64`, `AppendInt`, `AppendInt64`. The "primary" variant may omit it (`Marshal` and `MarshalText`).
- **Disambiguate near-identical names with a precise word**: `WriteTextTo`, `WriteBinaryTo` is fine when both coexist on the same type.

## Receivers

- **1–2 letters**, an abbreviation of the type.
- **Consistent across all methods of that type.**
- **Never** `this`, `self`, `me`. Never `_` unless the parameter is unused.

```go
// Good:
func (c *Config) Validate() error
func (c *Config) Save(w io.Writer) error

// Bad:
func (this *ReportWriter)
func (config *Config)
```

## Initialisms

Initialisms / acronyms preserve their case; they don't become Title Case.

| Concept | Exported | Unexported |
|---|---|---|
| XML API | `XMLAPI` | `xmlAPI` |
| iOS | `IOS` | `iOS` |
| gRPC | `GRPC` | `gRPC` |
| DDoS | `DDoS` | `ddos` |
| ID | `ID` | `id` |
| DB | `DB` | `db` |
| URL | `URL` | `url` |

So: `userID`, `URLPath`, `ServeHTTP`. Never `userId`, `UrlPath`, `ServeHttp`.

## Constants

`MixedCaps`, like everything else.

```go
// Good:
const MaxPacketSize = 512

// Bad:
const MAX_PACKET_SIZE = 512
const kMaxBufferSize = 1024  // no K-prefix C++ style
```

Name by *role*, not by value:

```go
// Bad:
const Twelve = 12
const UserNameColumn = "username"

// Good (whatever name describes role)
```

## Variables — scope and length

Length proportional to scope, inversely proportional to use frequency.

| Scope | Guideline |
|---|---|
| 1–7 lines | `c`, `i`, `n` are fine |
| 8–15 lines | single word: `count`, `users` |
| 15–25 lines | descriptive single word, possibly disambiguated: `userCount`, `pollInterval` |
| > 25 lines / file scope | full descriptive name |

- **Don't drop letters to save typing.** `Sandbox`, not `Sbx`. Especially in exported names.
- **Omit type-like words** from variable names. `users` (not `userSlice`), `userCount` (not `numUsers` or `usersInt`).
- **Disambiguate parsed/raw versions** with a qualifier: `ageString` for raw, `age` for parsed. Or `limitRaw` and `limit`.
- **Single letters** are fine for: loop indices (`i`, `j`), coordinates (`x`, `y`), readers/writers (`r`, `w`), short receivers.
- **Local variable names reflect *use*, not origin.** Often the local name should not match the struct field it came from.

## Repetition with surrounding context

Drop information that's already obvious from package, type, or function name.

```go
// Bad — package "ads/targeting/revenue/reporting"
type AdsTargetingRevenueReport struct{}

// Good
type Report struct{}
```

```go
// Bad — package "sqldb"
type DBConnection struct{}

// Good
type Connection struct{}
```

## Test doubles

Naming follows two paths.

**Single-type packages — concise:**

```go
// In package creditcardtest
type Stub struct{}              // creditcardtest.Stub reads cleanly
type Spy struct{ Charges []Charge }
```

**Multi-type packages — explicit:**

```go
// In package creditcardtest, multiple types being doubled
type StubService struct{}
type StubStoredValue struct{}
```

**Behaviour-specific stubs name themselves by behaviour:**

```go
type AlwaysCharges struct{}    // always succeeds
type AlwaysDeclines struct{}   // always returns ErrDeclined
```

**In tests, prefix the local variable to disambiguate from production types:**

```go
var spyCC creditcardtest.Spy   // good
var cc creditcardtest.Spy      // ambiguous with creditcard.Card etc.
```

## Util / common / helper packages — antipattern

`util`, `common`, `helper`, `model`, `testhelper`, `misc`: all bad package names. They:

- tell readers nothing about what's inside,
- collide with everyone else's `util`, forcing renames at every import site,
- become dumping grounds.

```go
// Good:
db := spannertest.NewDatabaseFromFile(...)
b := elliptic.Marshal(curve, x, y)

// Bad:
db := test.NewDatabaseFromFile(...)
b := helper.Marshal(curve, x, y)
```

If a `util` package already exists, prefer refactoring the package itself with a more suitable name over renaming at import.

## Shadowing

Short var declarations `:=` inside a new scope create a *new* variable. Code outside that scope sees the original.

```go
// Bad:
if *shortenDeadlines {
    ctx, cancel := context.WithTimeout(ctx, 3*time.Second)  // new ctx, scoped to the if!
    defer cancel()
}
// outside the if, `ctx` is still the original
```

Fix with simple assignment + outer declaration:

```go
// Good:
if *shortenDeadlines {
    var cancel func()
    ctx, cancel = context.WithTimeout(ctx, 3*time.Second)
    defer cancel()
}
```

Avoid using common package names (`url`, `path`, `time`) as local variable names — shadows the package for the rest of the function.

## Underscores

Generally forbidden in identifiers. Three exceptions:

1. Package names imported only by generated code may contain underscores (rare).
2. `Test*`, `Benchmark*`, `Example*` function names in `*_test.go` may contain underscores: `TestParse_emptyInput`.
3. Low-level cgo / syscall identifiers reusing OS names.

Filenames are *not* identifiers — they may use underscores.

## Package names

- Lowercase, no underscores, no `MixedCaps`.
- Concise — `tabwriter`, not `tab_writer` or `TabWriter`.
- Don't pick names that will be shadowed by common variables (`count` → use `usercount`).
- Avoid `util` / `common` / `helper` / `model`.
- Multi-word stays unbroken: `oauth2`, `httputil` (when scope is genuinely "http utilities").

## Renaming imports

- **Generated proto imports**: must be renamed to drop underscores, with `pb` suffix: `foopb "path/to/foo_go_proto"`. gRPC stubs: `foogrpc "..."`.
- **Collisions**: rename the *more local* / project-specific import.
- **Uninformative third-party names** (`util`, `v1`): rename sparingly, only when the surrounding code doesn't already provide context.
- **Collision with a desired local var**: rename the package with a `pkg` suffix (`urlpkg`).

```go
// Good:
import (
    foopb "path/to/foo_go_proto"
    core "github.com/kubernetes/api/core/v1"
)
```

## Named return parameters

Use them only when:

- The return values share a type and naming clarifies which is which: `func Children() (left, right *Node, err error)`.
- The caller must take a documented action on a returned value, and the name conveys that: `func WithTimeout(...) (ctx Context, cancel func())`.
- The value must be modified in a deferred closure.

Don't use them just to enable naked returns or to save a variable declaration. Naked returns are only acceptable in **small** functions.

```go
// Bad — pointless naming, repeats type
func (n *Node) Parent2() (node *Node, err error)

// Good
func (n *Node) Parent2() (*Node, error)
```
