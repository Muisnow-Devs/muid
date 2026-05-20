# Agent instructions (muid)

This repository is the **muid** Go monorepo (`module sanzi.io/muid`): gRPC services for **authentication** (`cmd/authn`), **user profiles** (`cmd/profile`), and a **NATS → SMTP mailer** (`cmd/mailer`). API contracts live under `api/proto/`; generated Go stubs live in `sanzi.io/muid/api` (replaced to `./api` in `go.mod`).

## Where to read more

- **[docs/ENGINEERING_GUIDE.md](docs/ENGINEERING_GUIDE.md)** — layout, bootstrap pattern, gRPC/NATS/Ent/mailer/profile/authn details, testing notes.
- **[.cursor/rules/muid.mdc](.cursor/rules/muid.mdc)** — non‑negotiable conventions aligned with this codebase.

## Engineering principles

- **Reuse before duplication:** extend or refactor shared helpers and existing modules (e.g. `pkg/*`, `infra/*`). Do **not** add a parallel “smaller duplicate” for the same concern (second HTTP client wrapper, second validation layer, …) unless the same change migrates callers off the old path.
- **Simple, obvious design:** prefer straightforward control flow, shallow modules, and clear data ownership; avoid clever patterns that hide behavior.
- **Names and splits:** name files, functions, and packages after domain behavior; split oversized files by concern when readability or debugging suffers.
- **Flat control flow:** prefer early returns, small private functions, typed handlers (`TopicHandler`-style), and composition helpers (`pkg/entpostgres.OpenEntPostgres`-style) over deeply nested lambdas or goroutine callbacks. Treat deep nesting as a smell—flatten when the logic is hard to follow at a glance, including in error branches (see **Do** and `.cursor/rules/muid.mdc` **Errors (inner vs boundary)**). Guideline, not a tool rule.

## Build, generate, test

| Task | Command (from repo root) |
|------|---------------------------|
| Protobuf (Buf build + Go/grpc codegen) | `buf build` then `buf generate --template buf.gen.yaml` (or `make proto` on Unix with Buf installed) |
| Ent code generation | `go generate ./internal/authn/ent/...` and `go generate ./internal/profile/ent/...` (each `generate.go` runs `ent generate ./schema`) |
| Compile a service | `go build -o bin/authn ./cmd/authn` (same for `profile`, `mailer`) |
| Tests | `go test ./...` |

**Note:** The root `Makefile` lists `authz` and `gateway` in `SERVICES`; only **`authn`**, **`profile`**, and **`mailer`** exist under `cmd/` today. Adjust targets or add binaries before relying on `make build` for missing commands.

## Configuration prefixes

Config is loaded with `pkg/shared.LoadConfig[T](prefix)` and `github.com/kelseyhightower/envconfig`. Environment variable names are **`PREFIX` + `_` + field tag** (e.g. `PROFILE_DATABASE_URL` for prefix `PROFILE` and field `DATABASE_URL`).

| Prefix | Service | Examples |
|--------|---------|----------|
| `AUTHN_` | Authn | `AUTHN_DATABASE_URL`, `AUTHN_REDIS_URL`, `AUTHN_NATS_URL`, `AUTHN_OTP_SECRET_KEY`, `AUTHN_OTP_SEND_COOLDOWN_SECONDS` (min delay between OTP sends for the same transition **and** the same normalized email recipient; default `60`, `0` disables both), `AUTHN_PROFILE_GRPC_ADDR`, `AUTHN_PROFILE_GRPC_TIMEOUT_SECONDS`, `AUTHN_REQUEST_TIMEOUT_SECONDS` |
| `PROFILE_` | Profile | `PROFILE_DATABASE_URL`, `PROFILE_NATS_URL`, `PROFILE_REQUEST_TIMEOUT_SECONDS`, `PROFILE_R2_*`, `PROFILE_PUBLIC_ASSETS_URL` |
| `MAILER_` | Mailer | `MAILER_NATS_URL`, `MAILER_SMTP_HOST`, `MAILER_SMTP_PORT`, `MAILER_SMTP_FROM`, optional `MAILER_SMTP_USERNAME`, `MAILER_SMTP_PASSWORD`, `MAILER_SMTP_SSL` |

## Do

- Follow **`infra/<backend>/interface.go`**: exported types/interfaces only; implementations in sibling `.go` files (not named `interface.go`). Pair **`errors.go`** with **`interface.go`** when callers need stable `errors.Is` / `errors.As` semantics.
- Use **`pkg/sqldb`** for `database/sql` + pgx stdlib driver; use **`pkg/entpostgres.OpenEntPostgres`** when wiring Ent + best‑effort `Schema.Create` at startup.
- Assemble protobuf messages with **opaque API** style: **`&T{}` + `Set*` / `Get*` / `Has*`** (and `&Child{}` for nested messages). Avoid `new(T)` for generated message types and avoid leaning on `*_builder` patterns.
- Chain gRPC unary interceptors like **`internal/authn/app/service.go`** / **`internal/profile/app/service.go`**: `TraceUnaryInterceptor` → `UnaryProtovalidateInterceptor` → service **`RequestContextInterceptor`** (parse IDs / wire session tokens, `log.WithAttrs`) → `RecoveryInterceptor` → `LoggerInterceptor` → `TimeoutInterceptor`. Handlers read validated values from context (`ProfileUserIDFromContext`, `WireSessionFromContext`, …) instead of repeating `uuid.Parse` / `log.WithAttrs`.
- For unexpected failures at RPC boundaries: log with **`pkg/log.LogUnexpected`** using **`log/slog.Attr`** (and **`log.WithAttrs`** with **`log.ProfileID`** / **`log.UserID`** / **`log.TransitionID`** accepting **`uuid.UUID`**, not strings); return **`grpcutils.GRPCInternalError()`** (fixed **`internal error`**) to clients. Use **`pkg/log`** for all logging (not stdlib **`log`**).
- Use **`errutil.Discard`**, **`errutil.Close`**, **`errutil.CloseIf`** instead of ad‑hoc `_ = close()` patterns in defer/cleanup paths.
- In functions with **multiple error checks**, use assign-then-check (`result, err = fn()` then `if err != nil { … }`) instead of repeated `if err := fn(); err != nil {`.
- **Single-shot** `if err := fn(); err != nil { … }` is fine for one call or trivial cleanup.
- Keep **error branches flat** (early returns, guards, small helpers); avoid nested `if err` / `errors.Is` ladders. Inner vs boundary error semantics: `.cursor/rules/muid.mdc` **Errors (inner vs boundary)**.

## Do not

- Put concrete implementations inside **`infra/*/interface.go`**.
- Put authn‑specific adapters (OTP, transition store, identity providers) in top‑level **`infra/*`** — they belong under **`internal/authn/infra/`**.
- Return raw internal errors or stack traces in gRPC status messages; do not put protovalidate violation blobs in the client‑visible status (server logs them with `trace_id`).
- Mutate **`UserAvatar`** history in place for “avatar changes”; new state is **append‑only INSERTs** (see engineering guide).
- Bypass **`pkg/validation.ValidUsername`** / proto rules when changing usernames in Go (normalize to lower case for storage as implemented in profile code).

When in doubt, match an existing service (`internal/authn`, `internal/profile`, `internal/mailer`) rather than introducing a new pattern.
