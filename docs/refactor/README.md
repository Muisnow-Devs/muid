# Architecture Refactor Plan Inventory

Status: Planned

This directory records the accepted findings from the architecture, protocol,
dependency, implementation, flow, and security audit requested by
`refactor-plan.md`. Each document owns one root problem. Breaking changes are
intentional; implementation must remove superseded APIs and paths rather than
preserving compatibility layers.

## Ownership model

- Authn owns accounts, credentials, federated identities, authentication
  transitions, sessions, access-token issuance, OIDC provider state, consent,
  codes, tokens, and signing keys.
- Authz owns organizations as authorization principals, membership, roles,
  permission policy, and authorization decisions.
- Profile owns user and organization presentation data, usernames, avatars,
  locale, timezone, biography, and public profile projections.
- Gateway owns internet/internal protocol translation, caller authentication at
  the edge, abuse protection, browser security, and explicit propagation of an
  authenticated principal. It does not become authoritative for account or
  authorization state.
- Mailer owns delivery of typed mail commands received from NATS.

The seven existing deployable binaries remain the target deployment layout.
Focused gRPC services may be split within a binary without creating another
microservice.

## Plan order

| Phase | Plan | Status | Classification | Depends on |
| --- | --- | --- | --- | --- |
| 0 | [Reachable Go dependency vulnerabilities](reachable-go-dependency-vulnerabilities.md) | Implemented | B | None |
| 0 | [Internal administrator allowlist fail-close](gateway-internal-admin-authority-boundary.md) | Implemented | B | None |
| 0 | [Public web security configuration](gateway-public-web-security-configuration.md) | Implemented | B | None |
| 0 | [Gateway runtime configuration contract](gateway-runtime-configuration-contract.md) | Implemented | B | None |
| 0 | [Gateway HTTP resource budget](gateway-http-resource-budget.md) | Implemented | B | Public web security configuration, runtime configuration |
| 0 | [Generated-code reproducibility](generated-code-reproducibility.md) | Implemented | S | None |
| 0 | [Gateway lifecycle ownership](gateway-lifecycle-ownership.md) | Implemented | S then B | None |
| 1 | [Service identity and principal propagation](service-identity-and-principal-propagation.md) | Implemented | S/B | Administrator allowlist fail-close, runtime configuration |
| 1 | [Internal administrator authentication boundary](gateway-internal-admin-authentication-boundary.md) | Implemented | S/B | Administrator allowlist fail-close, service identity |
| 2 | [Public and private profile contracts](profile-read-contracts-and-private-claims.md) | Planned | S/B | Service identity |
| 2 | [Domain event inventory and delivery](domain-event-inventory-and-delivery.md) | Planned | S/B | Generated-code reproducibility |
| 2 | [Authn gRPC service cohesion](authn-grpc-service-cohesion.md) | Planned | S | Profile contracts, service identity |
| 2 | [Account/profile provisioning](account-profile-provisioning.md) | Planned | S/B | Authn service cohesion, profile contracts, event delivery |
| 2 | [Organization/profile provisioning](organization-profile-provisioning.md) | Planned | S/B | Profile contracts, event delivery |
| 3 | [Gateway data-plane boundary](gateway-data-plane-boundary.md) | Planned | S/B | Authn service cohesion, profile contracts, account/organization provisioning, service identity |
| 4 | [Public gateway caller resolution](gateway-public-caller-resolution.md) | Planned | S | Gateway boundary, Authn service cohesion |
| 4 | [Atomic counter contract](atomic-counter-contract.md) | Planned | S/B | HTTP resource budget |

`S` means a structural change with intended behavior preservation. `B` means an
intentional behavioral or security change. Mixed plans must use separate
commits for structural moves and behavior changes, and must validate after each
category.

Phase 0 is implemented and accepted. Its final validation passed `make check`,
the full Go test suite, gateway race testing (152 tests across 20 packages),
`go vet ./...`, `go build ./...`, and clean root/API `govulncheck` scans. The
overall inventory remains planned until every later phase is implemented and
the final outside-in architecture audit passes.

## Consistency rules

1. Establish authenticated workload and delegated-user identity before relying
   on any new public/private RPC split.
2. Define domain events and delivery semantics before replacing synchronous
   provisioning calls with events.
3. Authn allocates account/user IDs; Authz allocates organization IDs. Profile
   never allocates an identity for another domain.
4. Public profile APIs never return authentication claims or storage keys.
5. `gateway-public` remains the browser auth/OIDC and GraphQL transport edge;
   authenticated product composition moves to the curated `gateway-services`
   BFF.
6. The internal gateway requires explicit administrator authority, and Authn
   and Authz admin servers independently enforce the authenticated admin
   principal.
7. Generated artifacts are updated only through pinned, verified generation
   commands.
8. Browser product operations remain GraphQL at `gateway-public`, but that
   adapter can call only `gateway-services`; it never calls Authz or Profile
   directly.

## Completion gate

Each plan remains `Status: Planned` until its implementation, tests, generation,
and stale-path searches pass. Then its proposal must be reconciled with the
actual result and changed to `Status: Implemented`. Final completion additionally
requires `go test ./...`, `go test -race` on concurrency-sensitive packages,
`go vet ./...`, `go build ./...`, `buf build`, generation drift checks,
`govulncheck ./...`, and an outside-in trace of representative synchronous and
asynchronous flows.
