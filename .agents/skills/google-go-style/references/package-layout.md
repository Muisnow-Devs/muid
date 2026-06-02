# Package Layout — detailed reference

Read this when starting a new package, splitting an existing one, deciding what goes in `internal/`, organizing imports, dealing with circular dependencies, or considering a `util`-style package.

## Package size

Pick cohesion over file count.

- Tightly-coupled types belong in **the same** package — they can share unexported identifiers without polluting the public API.
- Conceptually distinct functionality belongs in **separate** packages — short package + exported type combine into meaningful identifiers (`bytes.Buffer`, `ring.New`).
- A useful test: if a hypothetical user must import both `pkg/a` and `pkg/b` to use either meaningfully, combine them.
- Putting an entire project in one package is too large.
- The standard library models this well: `csv` is small (`reader.go` + `writer.go`); `http` is large but split across files (`client.go`, `server.go`, `cookie.go`).

## File structure

- **No "one type, one file" rule.** Group related code by file as the maintainer's index.
- Avoid extremes: not one giant file with thousands of lines, not many tiny files.
- A `doc.go` containing only the package comment and the package clause is acceptable for packages with long documentation.
- Files are an organisational tool — they don't affect callers, so move things between files freely.

## `internal/`

Packages under a directory named `internal` are importable only by code rooted at the parent of `internal`. Use it for:

- Implementation details you don't want third parties (or even other parts of the codebase) to depend on.
- Test-only packages: `internal/testutil` for shared test fixtures.
- Code that's not yet ready for a public API.

Anything *not* in `internal/` is part of the public API — assume external code depends on it.

## Avoid `util` / `common` / `helper` / `model` / `misc`

These names tell readers nothing about what's inside. They become dumping grounds. They collide with everyone else's `util`, forcing renames at every import site.

```go
// Bad:
import "myproj/util"
b := util.Marshal(...)

// Good:
import "myproj/elliptic"
b := elliptic.Marshal(...)
```

If you have a `util` package now, refactor: split it into domain-named packages. The util-package antipattern is one of the most common code-smell signals in Go.

A `util` substring is acceptable as *part* of a more specific name: `httputil`, `iotest`. Just `util` is not.

## Package names

- Lowercase, no underscores, no `MixedCaps`.
- Concise: `tabwriter`, not `tab_writer` / `TabWriter`.
- Descriptive: `oauth2`, not `auth`.
- Avoid names commonly used as local variables (`count`, `url`) — they will be shadowed everywhere.
- Multi-word stays unbroken: no `tab_writer`.

## Import organization

Three (or four) groups in this order, separated by blank lines:

1. **Standard library**
2. **Project + third-party** (vendored, external modules)
3. **Protocol Buffer imports** (e.g. `foopb "path/to/foo_go_proto"`)
4. **Side-effect blank imports** (`_ "path/to/package"`)

```go
// Good:
import (
    "fmt"
    "hash/adler32"
    "os"

    "github.com/dsnet/compress/flate"
    "google.golang.org/protobuf/proto"

    foopb "myproj/foo/proto/proto"

    _ "myproj/rpc/protocols/dial"
)
```

`goimports` enforces grouping; trust the tool.

## Blank imports `import _`

Allowed only in:
- `package main` (binaries)
- `*_test.go` test files
- Files using `//go:embed`
- Bypassing nogo static checker (rare exception)

NEVER use a blank import in a library package. Constraining side effects to binaries / tests preserves dependency control.

## Dot imports `import .`

**Forbidden** in the Google codebase. They make symbol provenance unclear.

## Proto imports

Generated proto packages must be renamed to drop underscores, with a `pb` (or `grpc`) suffix:

```go
// Good:
import (
    foopb     "path/to/package/foo_service_go_proto"
    foogrpc   "path/to/package/foo_service_go_grpc"
)
```

Prefer descriptive suffixed names (`pushqueueservicepb`) over very short ones (`xpb`, `pb`). Old code with short names doesn't need rewriting.

When the same proto is imported in multiple files, use the **same** local name everywhere for consistency.

## Renaming non-generated imports

Generally avoid. Acceptable when:

- The package name collides with another import.
- The package name is uninformative (`util`, `v1`) AND the surrounding code doesn't already provide context. Even then, prefer refactoring the package itself.
- The package name collides with a desired local variable (`url`, `path`); rename with `pkg` suffix: `urlpkg`.

```go
// Good:
import (
    core   "github.com/kubernetes/api/core/v1"
    meta   "github.com/kubernetes/apimachinery/pkg/apis/meta/v1beta1"
)
```

## Circular imports

If `pkg/a` imports `pkg/b` and `pkg/b` needs something from `a`, restructure:

- Move the shared concern into a third package both can import.
- Move the consumer-side interface into the consumer package — interfaces are defined where they're used, not where they're implemented.
- Combine the packages if they're truly tightly coupled.

Don't introduce blank-import side effects to break cycles.

## Test packages

`*_test.go` files can be in two packages:

- `package foo` — internal tests, can access unexported identifiers.
- `package foo_test` — external/black-box tests, exercise only the public API. Live in the same directory.

Both compile together for `go test`. Use `foo_test` for public-API tests, examples (`Example*`), and to verify the package can be used without internal access.

For multi-file integration / functional tests outside the package, separate directories with their own packages are common. The `_test` suffix on the package name (`linkedlist_test`) is allowed for these.

## File / directory conventions

- One Go module = one repository (typically). Module path matches the canonical import path.
- Each package has its own directory in open-source layout. (Inside Google, multiple `go_library` targets per directory are allowed via Bazel — open-source code shouldn't follow that pattern.)
- File names: lowercase, may contain underscores (file names are NOT identifiers, so the no-underscore rule doesn't apply).
- Test files: `<name>_test.go`.
- Example file: `example_<feature>_test.go` is conventional but not required.

## Dependency hygiene

Maintainable code minimises dependencies — both explicit (imports) and implicit (subtle reliance on undocumented behaviour).

- Fewer imports = fewer lines of external code that can break you.
- Don't depend on a third-party package's internal fields, undocumented behaviour, or pre-release APIs.
- Prefer the standard library when it suffices.
