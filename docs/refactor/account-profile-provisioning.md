# Account and Profile Provisioning

Status: Planned

Classification: S/B (ownership, persistence, and event-flow redesign)

# Problem

During registration, Authn asks Profile to allocate a user/profile ID and then
creates Authn's account reference. Failure or a lost response between those
steps can leave an orphaned Profile row; retry can allocate another identity.
Profile also accepts broad identity information owned by Authn.

# Evidence

- `api/proto/profile/v1/profile.proto` defines
  `CreateProfile(CreateProfileRequest{IdentityInformation})` returning a newly
  allocated ID.
- `internal/profile/grpc/profile_crud.go:CreateProfile` calls
  `core.Manager.CreateProfile` and returns that ID.
- `internal/profile/core/profile.go:CreateProfile` allocates the profile UUID
  and derives presentation from identity claims.
- Authn identity resolver/registration code holds a Profile client and calls
  `CreateProfile` before persisting the corresponding Authn user reference.
- Authn tests such as `internal/authn/accesstoken/minter_test.go` and
  `internal/authn/oidc/userinfo_test.go` require broad fake
  `ProfileServiceClient` implementations, demonstrating cross-domain coupling.

# Current Design

Profile is the ID allocator for a logical account, while Authn is authoritative
for credentials and identities. The operation is a non-transactional
Profile-to-Authn sequence with no idempotency key or compensation.

# Why This Is a Problem

Identity ownership is ambiguous and a routine timeout can permanently split the
domains. Retrying a non-idempotent allocator cannot safely determine whether the
first call committed.

# Proposed Design

Authn allocates `user_id` and commits the account, credential/federated identity,
and `AccountRegistered` outbox record in one transaction. Profile consumes the
fact and idempotently inserts a presentation row keyed by that supplied ID.
Profile chooses presentation defaults/username because it owns them, but never
creates or interprets authentication identity.

Profile availability does not determine whether authentication registration
succeeded. `UserGatewayService.GetMe` represents the interval as
`profile_state = PROFILE_STATE_PROVISIONING` with no profile message; public
profile lookup returns NotFound until the consumer creates it. The consumer
eventually creates the row. A workload-only, idempotent
`ProfileProvisioningService.EnsureUserProfile(user_id)` exists solely for repair
and backfill, not on the registration request path.

# Proposed API / Protocol Changes

- Remove `ProfileService.CreateProfile` and `CreateProfileRequest.identity`.
- Publish `AccountRegistered{event_id,user_id,occurred_at}` as defined in the
  event plan.
- Add no public replacement create RPC. Internal
  `ProfileProvisioningService.EnsureUserProfile(user_id)` is idempotent and only
  for repair/backfill.

# Dependency / Flow Changes

Current: `Authn -> Profile CreateProfile -> Authn account commit`.

Target: `Authn account+outbox commit -> response`; asynchronously
`outbox -> AccountRegistered -> Profile idempotent insert`.

# Security Implications

Authn remains the only authority that binds credentials to a user ID. Profile
consumers accept events only from the Authn subject/credential and cannot alter
Authn identity. Removing `IdentityInformation` reduces cross-domain disclosure.

# Affected Code

- Authn registration/identity resolver and Ent schema for outbox
- `api/proto/profile/v1/profile.proto`
- `internal/profile/{grpc,core}` and Ent schema
- new Profile account-event consumer
- Authn/Profile bootstrap dependencies, tests, and generated code

# Implementation Steps

1. Make Authn allocate user IDs and persist account plus outbox atomically.
2. Implement the event/outbox foundation from the event plan.
3. Add Profile's idempotent `AccountRegistered` consumer keyed by `user_id`.
4. Define missing-profile behavior for gateway reads and tests.
5. Backfill existing Profile rows/account IDs and remove redundant identity
   columns according to the profile-contract plan.
6. Remove Profile client use from registration and delete `CreateProfile`.

# Validation Criteria

- Authn registration succeeds while Profile is unavailable and creates exactly
  one account ID and outbox event.
- Replayed events create one Profile row with one stable username.
- Lost-response/crash tests eventually converge without orphan identities.
- Profile accepts no authentication identity/email claims during provisioning.
- Searches find no `CreateProfile` caller or obsolete message.
