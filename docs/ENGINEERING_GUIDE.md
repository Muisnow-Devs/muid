# muid engineering guide

This document describes how the **muid** monorepo is structured and how services are built. It supersedes the older agent styling notes for English-speaking contributors and Cursor agents. For a short agent entry point, see **[AGENTS.md](../AGENTS.md)**. For machine-oriented rules, see **[.cursor/rules/muid.mdc](../.cursor/rules/muid.mdc)**.

There is no separate frontend design system in this repo; the “contract surface” is **Protobuf + buf validate**, service boundaries, and **Go package layout**.

---

## Go module and generated API

- **Module:** `sanzi.io/muid`.
- **Generated API module:** `sanzi.io/muid/api`, replaced in `go.mod` with `replace sanzi.io/muid/api => ./api`.
- **Protobuf sources:** `api/proto/` under Buf module `sanzi.io/muid/proto` (`buf.yaml`).
- **Code generation:** `buf build` and `buf generate --template buf.gen.yaml` (see `buf.gen.yaml`). Go uses **opaque** messages (`protocolbuffers/go` with `default_api_level=API_OPAQUE`).
- **Assembling messages:** use **`&T{}`** plus **`Set*` / `Get*` / `Has*`** (including oneofs). For nested messages, allocate with **`&Child{}`** then `Set…`. Prefer **not** using `new(T)` for generated message types, and **not** relying on `*_builder{…}.Build()` as the default pattern—opaque style matches existing handlers.

**buf.validate:** field rules in `.proto` files (`import "buf/validate/validate.proto"`). Runtime validation for unary gRPC requests is enforced by **`pkg/grpc_utils.UnaryProtovalidateInterceptor`** (`buf.build/go/protovalidate`). On violations: gRPC **`InvalidArgument`** with fixed client text **`request validation failed`**; server logs include **`trace_id`** and full violation text (details are **not** copied into the status message). `buf.yaml` depends on **`buf.build/bufbuild/protovalidate`**; managed mode in `buf.gen.yaml` **disables `go_package`** for that module so generation stays compatible with the Go module layout.

---

## Monorepo layout

| Area | Role |
|------|------|
| **`cmd/<service>/main.go`** | Process entrypoints. Present today: **`authn`**, **`authz`**, **`profile`**, **`mailer`** (`cmd/gateway` is an empty placeholder). |
| **`internal/<domain>/`** | Domain logic per service (`internal/authn`, `internal/profile`, `internal/mailer`, plus shared packages like `internal/session`, `internal/identity`, `internal/media`, `internal/templates`). |
| **`infra/<backend>/`** | Reusable infrastructure: **interfaces in `interface.go`**, implementations in sibling files (`infra/redis`, `infra/nats`, `infra/smtp`, `infra/r2`, `infra/secretmanager`, `infra/mocked`, …). |
| **`pkg/`** | Shared libraries (`pkg/grpc_utils`, `pkg/log`, `pkg/sqldb`, `pkg/entpostgres`, `pkg/enttx`, `pkg/errutil`, `pkg/validation`, `pkg/shared`, …). Contracts such as **`pkg/shared/secretmanager.SecretManager`** live under **`pkg/shared/<name>/`**. |
| **`api/proto/`** | Protobuf definitions; generated `*.pb.go` under **`api/`** after `buf generate`. |

**Authn-only infrastructure** (OTP, transition store, OIDC/email/passkey providers tightly coupled to auth flows) lives under **`internal/authn/`** (`kv/`, `identity/`). Do **not** move those into top-level **`infra/*`**.

---

## Per-service bootstrap pattern

Each service follows the same broad shape:

1. **`cmd/<service>/main.go`** — load config with **`pkg/shared.LoadConfig[app.Config](app.ConfigEnvPrefix)`**, construct infra, construct app, start, graceful shutdown on signals.
2. **`internal/<service>/app/config.go`** — `envconfig` struct tags; **`ConfigEnvPrefix`** is `AUTHN`, `AUTHZ`, `PROFILE`, or `MAILER`.
3. **`internal/<service>/app/bootstrap.go`** (or equivalent) — **`New*Infra`**: open NATS/Redis/R2/SMTP as needed, open DB via **`pkg/entpostgres`**, register cleanup with **`errutil.Close` / `errutil.CloseIf`**.
4. **`internal/<service>/app/service.go`** (or similar) — gRPC server wiring, interceptor chain, `Register*Server`.

**Makefile:** `make proto` runs `buf build` and `buf generate`. `make build` targets a fixed `SERVICES` list that includes **`gateway`**; that **`cmd/`** tree is still an empty placeholder—use explicit `go build ./cmd/authn` (etc.) until it exists.

---

## Configuration (`envconfig`)

Use **`github.com/kelseyhightower/envconfig`** via **`pkg/shared.LoadConfig[T](prefix)`**.

- **Prefix convention:** service name + underscore (`AUTHN_`, `PROFILE_`, `MAILER_`).
- Struct fields use `envconfig:"FIELD_NAME"`; the full environment variable is **`PREFIX_FIELD_NAME`** (e.g. `PROFILE_DATABASE_URL`).

**Authn (`AUTHN_`):** `DATABASE_URL`, `REDIS_URL`, `NATS_URL`, `OTP_SECRET_KEY`, `REQUEST_TIMEOUT_SECONDS`, `OIDC_CLIENTS_JSON`, optional `PROFILE_GRPC_ADDR`, `PROFILE_GRPC_TIMEOUT_SECONDS`, … (see `internal/authn/app/config.go`). `OIDC_CLIENTS_JSON` is a JSON array of clients with `provider` (or `key`), `endpoint`, `client_id`, `client_secret`, `redirect_url`, optional `scopes`, and optional `claim_fields` mapping shared claims such as `picture` to provider fields like `avatar_url`.

**Profile (`PROFILE_`):** `DATABASE_URL`, `NATS_URL`, `REQUEST_TIMEOUT_SECONDS`, R2 and `PUBLIC_ASSETS_URL` fields (see `internal/profile/app/config.go`).

**Mailer (`MAILER_`):** `NATS_URL`, `SMTP_HOST`, `SMTP_PORT`, `SMTP_FROM`, optional `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_SSL` (see `internal/mailer/app/config.go`).

**Google Secret Manager (future service wiring):** contract **`pkg/shared/secretmanager`** (`SecretManager`, `SecretRef`, stable errors). GCP implementation **`infra/secretmanager`** — **`NewGCPSecretManager(ctx, GCPConfig{ProjectID, CredentialsFile})`** returns **`secretmanager.SecretManager`** (type alias to shared). Not loaded via `LoadConfig` yet; when wired, use env such as **`GSM_PROJECT_ID`** / **`GSM_CREDENTIALS_FILE`** (or `AUTHN_GSM_*` if authn-owned).

---

## gRPC interceptors (unary)

Unary servers in **authn** and **profile** use **`google.golang.org/grpc.ChainUnaryInterceptor`** in this order:

1. **`grpcutils.TraceUnaryInterceptor`** — injects log correlation id (`pkg/log` reads **`x-trace-id`** then **`x-request-id`**, else new UUID string via `shared.UUIDV7()`).
2. **`grpcutils.UnaryTracingInterceptor(tracer)`** — OpenTelemetry-style RPC spans via swappable **`pkg/shared/tracing.Tracer`** ([`infra/otel`](../../infra/otel) in prod, **`tracing.NewNoopTracer`** in tests/dev; pass `Debug: true` on noop for span lifecycle debug logs). Place after step 1 so spans include `muid.log_trace_id`. Constructor: **`oteltrace.NewTracer(oteltrace.Config{ServiceName, Enabled, Exporter: otlp|stdout|noop, OTLPEndpoint, Debug})`**.
3. **`grpcutils.UnaryProtovalidateInterceptor`** — buf validate / protovalidate; fixed client message on violations.
4. **Request context** — **`profilegrpc.ProfileRequestContextInterceptor`** or **`app.AuthnRequestContextInterceptor`**: after protovalidate, parse profile user ids / authn wire session tokens, attach **`log.WithAttrs`**, store typed values on context; return **`InvalidArgument`** before the handler on parse failures.
5. **`grpcutils.RecoveryInterceptor`**
6. **`grpcutils.LoggerInterceptor`**
7. **`grpcutils.TimeoutInterceptor`** — timeout from `RequestTimeoutSeconds` in service config (`AUTHN_REQUEST_TIMEOUT_SECONDS`, `PROFILE_REQUEST_TIMEOUT_SECONDS`, …).

Shared factory: **`grpcutils.UnaryRequestContextInterceptor`** — per-method enrichers keyed by `FullMethod`.

Reference implementations: **`internal/authn/app/service.go`**, **`internal/profile/app/service.go`**.

---

## Distributed tracing

- **Contract:** **`pkg/shared/tracing`** (`Tracer`, `Span`, `Attr`, `SpanOption`, stable errors in **`errors.go`**).
- **Implementations:** **`tracing.NewNoopTracer`** (tests, disabled); **`infra/otel`** (`oteltrace.NewTracer`) with OTLP HTTP or stdout exporters.
- **gRPC:** **`grpcutils.UnaryTracingInterceptor`** / **`UnaryTracingClientInterceptor`** (client stub).
- **Correlation:** log **`trace_id`** (`pkg/log`) is separate from OTel W3C trace id; linked on OTel spans as **`muid.log_trace_id`**.

### Instrumenting critical paths

Unary servers install the tracer on context (`tracing.ContextWithTracer`) before the RPC span. Handlers and shared helpers start child spans with **`tracing.StartSpan(ctx, "operation.name")`** (uses the context tracer, or noop when absent). Expensive work to cover: Ent transactions (**`tracing.WithSpanName(ctx, "profile.create_profile.tx")`** before **`enttx.Run`** — `enttx` reads the name and wraps commit/rollback), object storage (R2 presign/get/put), Redis/KV (OTP, transitions, session cache), outbound gRPC (authn → profile), NATS publish, and background avatar ingest (copy tracer from parent ctx in goroutines). Prefer a few well-named spans per RPC over annotating every helper.

---

## Errors and trace id

### Inner layers vs RPC boundary

- **Inner code:** prefer **sentinels** (`var ErrFoo = errors.New(…)`), **small typed errors** (optionally with `Detail()`), and **`errors.Join`** for multiple failures. Avoid long chains of `fmt.Errorf("…: %w", err)` except at a **single** top-level boundary (e.g. `cmd/*/main` startup) where one wrapping layer is acceptable.
- **Stable semantics** (e.g. **`pkg/shared/storage.ErrObjectNotFound`**): return the sentinel directly without an extra `%w` wrapper unless this layer is intentionally the semantic boundary.

### `interface.go` + `errors.go`

When **`interface.go`** defines the public contract for a package, **caller-visible failures** belong in sibling **`errors.go`** so clients use **`errors.Is` / `errors.As`**. Skip `errors.go` if the package has no meaningful stable error surface.

### Expected vs unexpected

- **Expected:** validation, business rules, not-found where that is part of the contract — map to appropriate **`grpc/codes`** and stable, non-sensitive status messages.
- **Unexpected:** DB/network/SDK bugs — at the handler or nearest boundary, call **`log.LogUnexpected`** with a short `reason`, safe `detail` (often `err.Error()` only when safe), and **`...slog.Attr`** (e.g. `slog.String("method", …)`, **`log.ProfileID`** / **`log.UserID`** / **`log.TransitionID`** (`uuid.UUID`) on ctx via **`log.WithAttrs`**, or per-call attrs). Return **`grpcutils.GRPCInternalError()`** so the client sees **`codes.Internal`** and the literal **`internal error`**, consistent with **`RecoveryInterceptor`**.

### Cleanup

Use **`errutil.Discard`**, **`errutil.Close`**, **`errutil.CloseIf`** instead of scattered `_ = x()` for defer cleanup.

---

## PostgreSQL and Ent

- **`pkg/sqldb`:** `OpenPostgres`, `EntDriverName()` (`pgx` stdlib driver registration via side-effect import). Ping after open; close on ping failure.
- **`pkg/entpostgres`:** **`OpenEntPostgres`** wraps `sqldb` + `entgo.io/ent/dialect/sql.OpenDB(dialect.Postgres, db)` + domain **`NewClient(…, Driver(drv))`**, then **`SchemaCreateBestEffort`**. Sentinels: **`ErrOpenPostgres`**, **`ErrSchemaCreate`** (often **`errors.Join`** with the driver error). On fatal schema failure, **`errutil.Close(client)`** runs before `onFatalCleanup`.
- **`pkg/enttx`:** **`Run` / `Do`** wrap **`client.Tx(ctx)`** — defer **`Rollback`**, **`Commit`** on success; pass **`g.db.Tx`** as `begin` and use the transactional client in the callback.
- **`SchemaCreateBestEffort`:** treats “already exists” / “duplicate” substrings as reuse (log + nil); other errors return **`errors.Join(ErrSchemaCreate, err)`** without closing the client.
- **Ent generate:** `internal/authn/ent/generate.go` and `internal/profile/ent/generate.go` contain `//go:generate go run entgo.io/ent/cmd/ent generate ./schema`.

**Manual Ent without `entpostgres`:** use **`dialect.Postgres`** with **`entsql.OpenDB`**, not raw `"pgx"` with **`ent.Open`** string dispatch.

---

## NATS, topics, and mailer

- **Abstraction:** **`pkg/shared/pubsub.PubSub`** (`Publish` / `Subscribe`).
- **NATS:** **`infra/nats.NewNATSPubSub`**. Each subscription handler runs with **`log.With(context.Background(), …)`** so logs include **`trace_id`** even without gRPC metadata.
- **Topic constants:** **`pkg/shared/topics`** (e.g. `mail.go`, `profile.go`) — strings like **`domain.action`** (e.g. `mail.send.otp`, `profile.change`).
- **Wire payloads:** protobuf **`proto.Marshal`** / **`proto.Unmarshal`** (same pattern as authn email publish path).

### Mailer `TopicHandler` pattern

Shared contracts live in **`internal/mailer/handlers`**:

- **`MailerDeps`** — `mailer.Mailer` + `templates.MailRenderer`.
- **`TopicHandler`** — `Topic() topics.Topic`, `SubscribeOptions() pubsub.SubscribeOptions`, `Handle(ctx context.Context, deps MailerDeps, payload []byte) error`.
- **`RegisterTopicHandlers`** — subscribes each handler; non-nil `Handle` errors are logged by the pubsub implementation with the topic.

Event-specific code goes under **`internal/mailer/handlers/<event>/`** (e.g. `otp`, `loginalert`) so **`internal/mailer/app`** only wires infra and calls **`handlers.RegisterTopicHandlers`** (`subscribers.go`), avoiding import cycles.

---

## Profile service

### Packages

- **Domain:** **`internal/profile/core`** (`core.Manager`) — owns the ent client, transactions, the patchable-field registry, avatar upload orchestration, and `profile.change` event publishing. Errors are sentinels / `core.InvalidArgumentError`, never gRPC statuses.
- **gRPC:** **`internal/profile/grpc`**, Go package name **`profilegrpc`** — thin adapters: proto↔domain mapping plus `mapProfileError` / `mapAvatarError` sentinel-to-status translation (same shape as authz).
- **App wiring / server lifecycle:** **`internal/profile/app`** (`bootstrap.go`, `service.go`, config).
- **NATS subscriber:** **`internal/profile/subscriber`** — e.g. **`RunProfileSubscriber`** unmarshals **`ProfileChangedEvent`** for `profile.change`.

### Shared claims and events

- **`api/proto/shared/v1/claims.proto`:** **`IdentityInformation`** is the single field shape for OIDC claims, profile create/update payloads, and **`ProfileChangedEvent.changes`**. Use **`google.protobuf.Timestamp`** for event times and similar fields (e.g. avatar presign expiry) where the contract uses timestamps.
- **Optional semantics:** use `optional` on proto fields when “field omitted” must differ from “empty value”.
- **Events:** `api/proto/event/v1/profile.proto` — **`changed_fields`** is a **`FieldMask`** over **`GetProfileResponse`**-level paths; **`changes`** is **`IdentityInformation`**; **`occurred_at`** is **`google.protobuf.Timestamp`**.

### `UpdateProfile` and FieldMask

- Request uses **`google.protobuf.FieldMask`** (`update_mask`) and **`optional IdentityInformation identity`**.
- Allowlisted paths normalize to **`identity.<proto snake_case>`** (e.g. `identity.email`, `identity.username`). JSON camelCase in the second segment is accepted and canonicalized (see package docs in **`internal/profile/updatemask`**).
- Parsing / tests: **`internal/profile/updatemask`**. DB mutators + event field mapping: the unified registry in **`internal/profile/core/fields.go`** (`profileFields`) — one entry per patchable path covers validation, the ent setter, and the `ProfileChangedEvent` claim.

### Usernames

- Proto: **`buf.validate`** pattern and length on `IdentityInformation.username` where defined.
- Go: **`pkg/validation.ValidUsername`** / **`UsernameCharsetRegex`** (`^[a-zA-Z0-9_]{5,32}$`) for updates; persisted usernames are lowercased with **`strings.ToLower`** where implemented.

### Avatars and `UserAvatar`

- **Display:** `GetProfile` **`avatar_url`** comes from **`UserAvatar`**: among rows for the user with **non-nil `uploaded_at`**, the row with **largest `id`** (UUID v7) wins. Staging rows (`uploaded_at` unset) do not participate.
- **Append-only:** avatar changes are **new INSERTs**, not UPDATE-in-place of historical rows. Immutable fields (`user_id`, `object_key`, `content_type`, …) must not be rewritten after insert—express new state with a new row (including staging vs completed upload flows).
- **Async ingest:** OIDC picture download / **`goavatar`** fallback, raster processing, R2 upload, and **`INSERT user_avatars`** run via **`internal/profile/avataringest`** (`ExternalAvatarIngestor.GoBootstrap`, goroutine + timeout context + panic recovery + trace id). **`CreateProfile`** commits the profile first, returns success, then schedules this work—**do not** block the RPC on ingest.
- **CreateProfile naming:** usernames come from **`randomUsernameBase`** + **`allocateUsername`** (not email local-part); display names from identity helpers with fallbacks (see profile gRPC / app code).

### Media / `CompleteAvatarUpload`

- **`internal/media`:** **`RasterAvatarProcessor`** / **`WebPRasterAvatarProcessor`**, limits and typed errors in **`errors.go`** next to **`interface.go`**.
- **Staging trust:** R2 **`HeadObject`** `ContentLength` is authoritative vs client hints; **`ValidateAvatarStagingObject`** does MIME/sniff/dimension guards before **`ProcessToSquareWebP`**.

---

## Authn service

- **Transition state:** **`internal/session`** (`AuthFlowKind`, `EmailOTPFlow`, `OIDCFlow`, `PasskeyFlow` pointers on `SessionStore`) with Redis backing **`internal/authn/kv`** implementing **`internal/session.AuthTransitionStore`**.
- **Identity providers:** **`internal/authn/identity`** implement **`internal/identity.IdentityProvider`**; **`internal/authn/app/handler.go`** routes **`ContinueAuthSession`** using transition `Provider` and maps `proof` into **`ContinueInput.Payload`**.
- **Account domain:** **`internal/authn/account`** exposes small interfaces (`Provisioning`, `Email`, `OIDC`, `Federated`, `Passkey`, `Session`, `LoginNotifier`) wired via **`account.Wire`** in bootstrap; callers inject only what they need. Profile **`CreateProfile`** when configured; session token shape per proto. Profile gRPC dial attaches **`log.UnaryClientInterceptor()`** for **`x-trace-id`**.

---

## Authz service (Casbin)

Authz is the organization/RBAC authority, built on **casbin v2** with domain (= organization UUID) RBAC.

- **Permission strings:** **`<namespace>/<resource>.<action>`** (e.g. `organization/oidc_client.write`, `organization/member.write`). The namespace is the resource domain (`organization`), not the owning service. The **slash** is deliberate — OIDC scopes use `namespace:resource.action` (colon) and permissions must stay visually distinct. Shared model + parse helpers live in **`pkg/shared/authzmodel`** (casbin obj = `namespace/resource`, act = `action`).
- **Rule storage:** the **`casbin_rule`** table (Ent schema `CasbinRule`, ptype + v0–v5), written **only** by **`internal/authz/policy.Manager`** in the same `enttx` transaction as the relational rows. `OrganizationRole` holds role metadata only (the old `RolePermission` table is gone — drop it manually in existing databases: `DROP TABLE IF EXISTS role_permissions;`). `OrganizationMember` rows are mirrored to `g, user:<uuid>, role:<name>, <orgID>` rules.
- **System roles:** `owner > admin > manager > member`, seeded per organization, hierarchy + default grants come from the **static policy config** (`internal/authz/policy/default_policy.json`, overridable via `AUTHZ_POLICY_CONFIG_PATH`/`_JSON`) as wildcard-domain (`*`) rules; `policy.Manager.Reconcile` diffs them idempotently at startup and on the `ReloadPolicyConfig` admin RPC. Guard rails: only owners grant/revoke `owner`; the last owner cannot be removed/demoted; system roles are immutable.
- **Two listeners:** public **`AUTHZ_PORT`** serves `AuthzUserService` (my orgs/permissions) + `AuthzOrganizationAdminService` (role CRUD, member management; each RPC casbin-enforced, e.g. `organization/role.write`) — identity comes from the gateway-injected **`x-user-id`** metadata (`authzgrpc.UserIdentityInterceptor`; authz never verifies tokens, so this listener must sit behind the gateway). Internal **`AUTHZ_INTERNAL_PORT`** serves `AuthzService` (service-to-service checks + `ListNamespacePolicies`/`ListUserOrganizationRoles` relation loading) + `AuthzAdminService` (IdP/platform management, no per-RPC auth) and must never be gateway-exposed.
- **Events:** every committed mutation publishes **`muid.event.v1.authz.PolicyChangedEvent`** on **`authz.policy.changed`** (`pkg/shared/topics`); authz replicas reload on foreign events (`origin_instance_id` skips self), and a periodic `LoadPolicy` (`AUTHZ_POLICY_RELOAD_SECONDS`) is the drift safety net. Transport is NATS today via `pkg/shared/pubsub` (GCP Pub/Sub can swap in behind the same contract).
- **Consuming services:** **`pkg/authzclient.Enforcer`** embeds a local casbin enforcer — it loads the service's namespace rules from `ListNamespacePolicies`, resolves user roles on demand (Redis-cached, `ListUserOrganizationRoles`), and invalidates on `authz.policy.changed`; decisions are local, no per-check RPC. Authn wires it in `wireOIDCProviderInfra` (`AUTHN_AUTHZ_GRPC_ADDR` → **internal** listener; `AUTHN_AUTHZ_ROLE_CACHE_TTL_SECONDS`, `AUTHN_AUTHZ_POLICY_REFRESH_SECONDS`) and adapts it via `internal/authn/oidc/policy.LocalEnforcerAccess`.

---

## User id naming across layers

| Layer | Convention | Example |
|-------|------------|---------|
| Protobuf | `snake_case` field | `user_id` |
| JSON / `json_name` | camelCase | `userId` |
| Hand-written Go | `userId` / `UserId` | `userId := uuid.Parse(...)` |

Generated Go getters for `user_id` often appear as **`GetUserId()`**; Ent uses **`UserID`** for `field.UUID("user_id", …)`. Keep **semantic** “one user id” consistency; avoid legacy names like `profile_id` for the same concept.

---

## Conventions

### Engineering principles

These align with **[AGENTS.md](../AGENTS.md)** and **[.cursor/rules/muid.mdc](../.cursor/rules/muid.mdc)**; they describe how to grow the codebase without parallel implementations or unreadable structure.

- **Reuse before duplication:** prefer extending **`pkg/*`**, **`infra/*`**, or an existing service package over a new “lightweight copy” of the same idea. A second HTTP stack, validator, or DB open helper “just for this RPC” is usually wrong—fold behavior into the shared module or refactor callers in one migration. Exception: you are explicitly replacing the old implementation **in the same change** and deleting or deprecating the duplicate.
- **Simple, obvious design:** linear happy paths, shallow packages, and explicit ownership of state (who opens/closes a client, who owns a goroutine lifetime). Reserve abstractions for repeated shape, not one-off cleverness.
- **Names and splits:** pick names from the domain (`CompleteAvatarUpload`, `OpenEntPostgres`, `TopicHandler`), not generic placeholders. When a file mixes unrelated concerns (e.g. RPC wiring + SQL + ad-hoc validation) and navigation becomes painful, split along those seams into focused files or small private types—**not** micro-files for every function.
- **Flat control flow:** use guard clauses and extracted helpers instead of pyramids of `if`/`for`/anonymous funcs. For async boundaries, follow established patterns: **`TopicHandler.Handle`**, **`OpenEntPostgres`** composition, mailer wiring in **`internal/mailer/app`**. If nesting makes the happy path hard to see, refactor—treat “roughly how deep is too deep” as a readability guideline rather than a linter threshold.

**Duplication (bad vs good).**

```text
// Bad: new username checks in a handler because pkg/validation feels "too heavy".
func updateProfile(ctx, req) error {
    if !regexp.MustCompile(`^[a-z0-9_]{5,32}$`).MatchString(req.Username) { … }
}

// Good: one policy in pkg/validation (and proto buf.validate); handlers call it.
func updateProfile(ctx, req) error {
    if !validation.ValidUsername(req.GetUsername()) { … }
}
```

**Nesting (bad vs good).**

```text
// Bad: nested anonymous work obscures failure paths.
subscribe(ctx, topic, func(msg) {
    go func() {
        process(msg, func(err) {
            if err != nil { log(err); return }
            send(func(err) { … })
        })
    }()
})

// Good: typed handler, early returns, explicit error propagation (see mailer TopicHandler).
func (h *OTPHandler) Handle(ctx context.Context, deps MailerDeps, payload []byte) error {
    req, err := parse(payload)
    if err != nil {
        return err
    }
    if req.Skip {
        return nil
    }
    return h.renderAndSend(ctx, deps, req)
}
```

---

## Templates (mailer)

- **`internal/templates`:** `go:embed` for `layouts/`, `pages/<name>/content.html|txt`, `locales/<lang>/<page>.json`.
- **`Render`:** validates `locale` and `page` as single path segments (reject `.`, `..`, slashes, NUL, …). Expected failures surface as **`templates.ErrInvalidTemplatePath`** (see **`internal/templates/errors.go`** next to **`interface.go`**).

---

## Testing conventions

- Prefer **table-driven** tests and **`t.Run`**; use **`t.Parallel()`** when tests do not share mutable globals or ports.
- Keep **`internal/profile/updatemask`**-style packages free of Ent/DB imports so path/mask logic stays fast and isolated.
- Run **`go test ./...`** from the repo root for a full sweep.

---

## Quick file index

| Topic | Location |
|-------|----------|
| Authn gRPC server | `internal/authn/app/service.go` |
| Authn infra wiring | `internal/authn/app/bootstrap.go`, `cmd/authn/main.go` |
| Profile gRPC server | `internal/profile/app/service.go` |
| Profile infra wiring | `internal/profile/app/bootstrap.go`, `cmd/profile/main.go` |
| Profile gRPC handlers | `internal/profile/grpc` (`package profilegrpc`) |
| Profile NATS | `internal/profile/subscriber` |
| gRPC utils / protovalidate | `pkg/grpc_utils/` |
| Username validation | `pkg/validation/username.go` |
| Mail events proto | `api/proto/event/v1/mail.proto` |
| Profile events proto | `api/proto/event/v1/profile.proto` |
| Topic constants | `pkg/shared/topics/mail.go`, `pkg/shared/topics/profile.go` |

---

## Changelog of docs

- **`docs/AGENT_STYLING.md`** is deprecated; it pointed here. All long-form English guidance lives in this file.
