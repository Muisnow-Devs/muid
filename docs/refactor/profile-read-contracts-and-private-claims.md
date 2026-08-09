# Public and Private Profile Contracts

Status: Planned

Classification: S/B (protocol split and data-ownership correction)

# Problem

One `ProfileService.GetProfile(id)` contract serves public lookup,
self-service, Authn claims, and gateway composition. Its response combines
public presentation with email, original identity, locale/timezone, and avatar
storage keys. The request-context interceptor can derive authority from the
requested ID rather than the authenticated subject.

# Evidence

- `api/proto/profile/v1/profile.proto` defines `ProfileService.GetProfile` with
  caller-supplied `id` and a response containing `email`, `avatar_object_key`,
  and `original_identity` alongside public fields.
- `internal/profile/grpc/profile_crud.go:GetProfile` maps all those fields.
- `internal/profile/grpc/request_ctx.go:enrichGetProfile` handles the request ID
  specially and is tested with arbitrary IDs.
- `internal/gatewaypublic/graph/resolver.go:profileByID` and its request loader
  use the same RPC for public/member presentation.
- `internal/gatewayservices/grpc/handler.go:GetMe` uses the same RPC for a
  private self response.
- Authn OIDC/user-info and access-token code has Profile client dependencies,
  while Authn already owns account identities and verified email.

# Current Design

Field privacy depends on each caller ignoring fields it did not need. Profile
stores and returns identity claims that overlap Authn ownership. An explicit
request ID can become the request context's user ID.

# Why This Is a Problem

The protocol does not express public versus self authority. A newly added caller
can accidentally disclose private claims or storage implementation details, and
request data must never establish authenticated identity.

# Proposed Design

Split focused services in the existing Profile binary:

- `PublicProfileService.GetPublicProfile(GetPublicProfileRequest{id})` returns
  only `id`, `username`, `display_name`, `avatar_url`, and `bio` (plus other
  deliberately public presentation fields accepted by product policy).
- `MyProfileService.GetMyProfile(GetMyProfileRequest{})` derives the subject
  only from verified delegated principal and returns private user-editable
  presentation such as locale/timezone.
- `MyProfileService.UpdateMyProfile(UpdateMyProfileRequest{patch, update_mask})`
  similarly has no user ID.
- Authn exposes its own `AccountService.GetMyAccount` contract for private
  account claims; it does not read them back from Profile.

Remove email and federated/original identity from Profile persistence and
protocols; Authn is authoritative for them through the account contract in
`authn-grpc-service-cohesion.md`. Never expose `avatar_object_key` on network
APIs; avatar workflows use opaque upload/finalization operations.

# Proposed API / Protocol Changes

Replace `ProfileService.GetProfile`, `UpdateProfile`, and caller-allocating
`CreateProfile` with the focused contracts above and provisioning described in
the account plan. Use distinct `PublicProfile` and `MyProfile` messages; do not
embed one broad message and rely on field omission.

# Dependency / Flow Changes

Public lookup requires authenticated workload identity but no delegated user.
Self lookup/update requires both trusted workload and delegated user. The BFF
composes `AccountService.GetMyAccount` and `MyProfileService.GetMyProfile` with
the explicit partial-failure semantics defined by the Authn service plan.

# Security Implications

Finding classification: `Architectural Security Risk`.

The split enforces least disclosure and prevents a request ID from becoming an
authenticated subject. Backend service identity remains required; otherwise a
caller could select the more privileged service directly.

# Affected Code

- `api/proto/profile/v1/profile.proto`
- `internal/profile/grpc/{profile_crud.go,request_ctx.go}` and Profile core/Ent
  schema/migrations
- Authn access-token/OIDC Profile callers
- gateway public loaders/resolvers and services handler
- generated code and protocol tests

# Implementation Steps

1. Define public/self messages and explicit interceptor policy per full method.
2. Migrate public gateway/member lookups to `GetPublicProfile`.
3. Migrate `GetMe` and updates to no-ID self methods and the Authn account
   contract.
4. Move email/original identity reads to Authn-owned queries and remove those
   fields from Profile writes, storage, events, and responses.
5. Replace avatar object-key exposure with opaque avatar operations.
6. Remove old broad RPCs/messages and stale caller-ID enrichment.

# Validation Criteria

- Public profile descriptors contain no email, original/federated identity,
  locale/timezone (unless explicitly public), or object storage key.
- Self RPCs reject missing/mismatched delegated principals and accept no user ID.
- Public lookup of another user never changes caller identity in context.
- Searches find no old `GetProfile` call and no Profile-owned email/original
  identity field.
- Protocol, authorization, gateway, and migration tests pass.
