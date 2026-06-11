# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

**muid** is a Go monorepo (`module sanzi.io/muid`, with a nested `sanzi.io/muid/api` module replaced to `./api` via `go.work`/`go.mod`) of gRPC microservices: **authn** (authentication flows), **authz** (authorization/tokens), **profile** (user profiles), and **mailer** (NATS → SMTP). API contracts are Protobuf under `api/proto/`; generated stubs land under `api/`.

## Primary documentation — read these first

- **[AGENTS.md](AGENTS.md)** — agent entry point: conventions, config env-var prefixes, do/don't lists.
- **[docs/ENGINEERING_GUIDE.md](docs/ENGINEERING_GUIDE.md)** — full architecture: bootstrap pattern, interceptor chain, Ent/NATS/mailer/profile/authn details.
- **[.cursor/rules/muid.mdc](.cursor/rules/muid.mdc)** — non-negotiable code rules (error handling, `infra/*` layout, protobuf opaque API, testing).
- **`.agents/skills/google-go-style/`** — Google Go style references.

**Known doc drift:** AGENTS.md and the engineering guide say only `authn`/`profile`/`mailer` exist under `cmd/`. That is outdated — `cmd/authz` and `internal/authz` now exist (gRPC + Ent + token packages), and `cmd/gateway` is a placeholder (empty). Also, `internal/identity` has grown into subpackages (`issuer/`, `method/`, `policy/`, `resolver/`, `store/`), and authn handlers now live in `internal/authn/grpc` with OIDC/passkey config parsing in `internal/authn/config`. Trust the code over the docs where they disagree.

## Commands

```sh
# Protobuf codegen (Buf; regenerates *.pb.go under api/)
buf build
buf generate --template buf.gen.yaml      # or: make proto

# Ent codegen (after editing internal/<service>/ent/schema)
go generate ./internal/authn/ent/...
go generate ./internal/profile/ent/...
go generate ./internal/authz/ent/...

# Build a service (make build cross-compiles linux/amd64; use plain go build locally)
go build -o bin/authn ./cmd/authn         # same for authz, profile, mailer

# Tests
go test ./...                             # full sweep from repo root
go test ./internal/profile/updatemask/    # single package
go test -run TestName ./internal/authn/app/   # single test

# Mailer manual-test NATS publishers
make test-publish-tools                   # builds cmd/test/test-publish-* into bin/
```

There is no lint config in the repo; `go vet ./...` is the baseline check.

## Architecture (big picture)

Every service follows the same four-layer bootstrap shape — when adding anything, match an existing service rather than inventing a new pattern:

1. `cmd/<service>/main.go` — load config via `pkg/shared.LoadConfig[app.Config](app.ConfigEnvPrefix)` (envconfig; env vars are `AUTHN_`/`AUTHZ_`/`PROFILE_`/`MAILER_` + field tag), construct infra, start, graceful shutdown.
2. `internal/<service>/app/config.go` — envconfig struct.
3. `internal/<service>/app/bootstrap.go` — open NATS/Redis/R2/SMTP/Postgres (`pkg/entpostgres.OpenEntPostgres` for Ent), cleanup via `pkg/errutil`.
4. `internal/<service>/app/service.go` — gRPC server with the standard interceptor chain: Trace → OTel tracing (`pkg/shared/tracing` + `infra/otel`, noop when nil) → protovalidate → service request-context → Recovery → Logger → Timeout.

Key boundaries:

- **`infra/<backend>/`** (redis, nats, smtp, r2, otel, secretmanager, mocked) — generic drivers only. `interface.go` holds *only* exported interfaces/config; implementations in sibling files; stable errors in `errors.go`. Authn-coupled adapters (OTP, transition store, identity providers) live under `internal/authn/`, never top-level `infra/`.
- **`pkg/`** — shared libs: `pkg/log` (trace-id logging — always use this, never stdlib `log`), `pkg/grpc_utils`, `pkg/sqldb`/`pkg/entpostgres`/`pkg/enttx`, `pkg/errutil`, `pkg/validation`, `pkg/shared` (config, pubsub, topics, tracing contracts).
- **`internal/session`** — typed auth-transition state (`AuthFlowKind`: email_otp/oidc/passkey with typed pointers, not `map[string]any`); Redis backing in `internal/authn/kv`.
- **`internal/identity`** — identity-provider abstraction (issuer/method/policy/resolver/store) consumed by authn.
- **Cross-service comms:** gRPC (authn → profile `CreateProfile`, dialed with `log.UnaryClientInterceptor()` to forward `x-trace-id`) and NATS pub/sub (`pkg/shared/pubsub.PubSub`, topics in `pkg/shared/topics`, protobuf-marshaled payloads). Mailer consumes topics via the `TopicHandler` pattern in `internal/mailer/handlers/<event>/`.

## Non-negotiable conventions (summary — full detail in .cursor/rules/muid.mdc)

- **Protobuf opaque API:** build messages with `&pb.T{}` + `Set*`/`Get*`/`Has*`; never `new(pb.T)` or `*_builder` as default style.
- **Errors:** inner layers use sentinels/typed errors/`errors.Join`, not `fmt.Errorf("%w")` chains (one wrap allowed at `cmd/*/main` boundaries). At RPC boundaries, unexpected failures → `log.LogUnexpected` with `slog.Attr` (use `log.ProfileID`/`UserID`/`TransitionID` taking `uuid.UUID`) and return `grpcutils.GRPCInternalError()`. Never leak raw errors or protovalidate violations into client-visible status messages. Multiple error checks: assign-then-check, flat early-return branches.
- **Cleanup:** `errutil.Discard`/`Close`/`CloseIf`, not ad-hoc `_ = x.Close()`.
- **Reuse before duplication:** extend `pkg/*`/`infra/*` instead of adding parallel small copies of the same concern.
- **Profile specifics:** `UserAvatar` rows are append-only INSERTs (never mutate history); username changes go through `pkg/validation.ValidUsername` and are lowercased for storage; avatar ingest (`internal/profile/avataringest`) is async — never awaited inside the `CreateProfile` handler.
- **Tests:** table-driven, `t.Run` subtests, `t.Parallel()` where safe; keep pure-logic packages (e.g. `internal/profile/updatemask`) free of Ent/DB imports.
