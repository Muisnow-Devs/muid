# Documentation — detailed reference

Read this when writing godoc comments for exported (or non-trivial unexported) symbols, package documentation, runnable examples, or doc comments about errors / contexts / cleanup / concurrency.

## Doc comments — the basics

- **All top-level exported names must have doc comments.** Same for unexported types/functions with non-obvious behaviour.
- **Start with the symbol's name** as the first word: `// Encode writes the JSON encoding of req to w.` An article (`A`, `An`, `The`) may precede it: `// A Request represents a request to run a command.`
- **Full sentences, capitalized, period at the end.**
- **Doc comment immediately precedes the symbol** with no blank line between.
- **No tag-style annotations** (`@param`, `@returns`). Plain prose.
- **Document WHY, not WHAT.** The code already says what.

```go
// Good:
// A Request represents a request to run a command.
type Request struct { ... }

// Encode writes the JSON encoding of req to w.
func Encode(w io.Writer, req *Request) { ... }
```

For struct fields: short end-of-line phrases assuming the field name as subject are fine.

```go
// Good:
type Server struct {
    BaseDir         string  // base directory under which works are stored
    WelcomeMessage  string  // displayed when user logs in
    PageLength      int     // lines per page when printing (optional; default: 20)
}
```

## Package comments

One file in the package has a `// Package foo ...` (or `/* ... */`) comment immediately above its `package foo` clause. No blank line between.

```go
// Good:
// Package math provides basic constants and mathematical functions.
//
// This package does not guarantee bit-identical results across architectures.
package math
```

If multiple files, exactly one carries the package comment. For long docs, a `doc.go` file containing only the comment + the package clause is acceptable.

For `package main`: use the binary's name (matching the BUILD rule):

```go
// Good:
// The seed_generator command generates a Finch seed file from JSON configs.
package main
```

## What to document

### Errors

Document significant sentinel errors and error types your function returns:

```go
// Good:
// At end of file, Read returns 0, io.EOF.
func (*File) Read(b []byte) (int, error)
```

If a function returns a *typed* error (`*PathError`), say so — it tells callers how to use `errors.As`:

```go
// Good:
// If there is an error, it will be of type *PathError.
func Chdir(dir string) error
```

For package-wide error conventions, document them on the package itself:

```go
// Good:
// Package os ...
//
// Often, more information is available within the error. For example, ...
// the error will be of type *PathError, which may be unpacked for more
// information.
package os
```

### Cleanup contracts

If the API hands the caller a resource they must release, say so:

```go
// Good:
// NewTicker returns a new Ticker.
//
// Call Stop to release the Ticker's associated resources when done.
func NewTicker(d Duration) *Ticker
```

Make non-obvious cleanup explicit:

```go
// Good:
// Get issues a GET to the specified URL.
//
// When err is nil, resp always contains a non-nil resp.Body.
// Caller should close resp.Body when done reading from it.
func (c *Client) Get(url string) (resp *Response, err error)
```

### Concurrency safety — only when non-obvious

Default assumptions:
- Read-only operations are safe for concurrent use.
- Mutating operations are NOT safe.

You don't need to document either default. Document only when the actual behaviour differs:

- Operation looks read-only but isn't (e.g. LRU cache `Lookup` mutates internal state):

  ```go
  // Lookup returns the data associated with the key from the cache.
  //
  // This operation is not safe for concurrent use.
  func (*Cache) Lookup(key string) ([]byte, bool)
  ```

- API provides synchronization despite a mutating-looking method:

  ```go
  // NewFortuneTellerClient returns an *rpc.Client for the FortuneTeller service.
  // It is safe for simultaneous use by multiple goroutines.
  ```

- API consumes a user-implemented type with concurrency requirements:

  ```go
  // A Watcher reports the health of some entity.
  //
  // Watcher methods are safe for simultaneous use by multiple goroutines.
  type Watcher interface { ... }
  ```

If a type provides synchronisation in entirety, document on the *type*, not on every method.

### Contexts — usually nothing to say

Implicit by the type:
- Cancelling the context interrupts the function.
- The function's returned error in that case is `ctx.Err()`.

Don't restate these. Don't write `// Run processes work until the context is cancelled and accordingly returns an error.`

DO document context behaviour when:

- The function returns an error other than `ctx.Err()` on cancellation:

  ```go
  // If the context is cancelled, Run returns a nil error.
  ```

- The function has additional cancellation or lifetime mechanisms:

  ```go
  // Run processes work until the context is cancelled or Stop is called.
  ```

- The function has unusual context expectations:

  ```go
  // The context should not have a deadline.
  func NewReceiver(ctx context.Context) *Receiver

  // The context must have a value attached to it from security.NewContext.
  func Principal(ctx context.Context) (string, bool)
  ```

  (Avoid designing such APIs in the first place — but document if you must.)

### Function parameters and config fields

Don't enumerate every parameter mechanically:

```go
// Bad — adds nothing:
// Sprintf formats according to a format specifier and returns the resulting string.
//
// format is the format, and data is the interpolation data.
```

Document the *non-obvious* or *error-prone* aspects:

```go
// Good:
// Sprintf formats according to a format specifier and returns the resulting string.
//
// If the data does not match the expected format verbs or the count is off,
// the function inlines warnings about formatting errors into the output string.
```

## Examples

Runnable examples (`func ExampleX()` in `*_test.go`) appear in godoc and run as part of `go test`. Far better than commenting code samples — they're verified.

```go
// Good:
func ExampleConfig_WriteTo() {
    cfg := &Config{Name: "example"}
    if err := cfg.WriteTo(os.Stdout); err != nil {
        log.Exitf("Failed to write config: %s", err)
    }
    // Output:
    // {
    //   "name": "example"
    // }
}
```

## Godoc formatting

- **Blank line separates paragraphs.**
- **Two-space indentation** formats the lines verbatim (used for code blocks, lists, tables).
- **A single capitalized line followed by another paragraph** becomes a heading — autogenerated anchor for linking.
- Long URLs and long literal text on a single line are fine — godoc renders without forced wrapping.

```go
// Good:
// LoadConfig reads a configuration out of the named file.
//
// LoadConfig treats the following keys specially:
//   "import" — make this configuration inherit from the named file
//   "env"    — populate from system environment
```

## Comment line length

No fixed limit. Aim for ~80–100 columns, but don't break long URLs or strings just to fit. Be consistent within a file.

Avoid comments that fit huge amounts of text on one line — bad reader experience in editors that don't soft-wrap.

## Comments inside function bodies

Same WHY-not-WHAT rule. Notes on subtle invariants, hidden constraints, references to external bugs / specs / decisions are valuable. Restating what the next two lines do is noise.

When a piece of code is unusually structured or "stands out", it's often for a real reason — a comment briefly stating the reason helps readers know not to "simplify" it.

## File-level comments after imports

Comments aimed at maintainers (not godoc readers), placed *after* the import block, describe the whole file. They are not surfaced in godoc.

```go
package foo

import (
    "fmt"
)

// This file implements the v2 protocol; the v1 implementation lives in v1.go.
// Do not call helpers from v1.go from this file — they assume v1 framing.
```
