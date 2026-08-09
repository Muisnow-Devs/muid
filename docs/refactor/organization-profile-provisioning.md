# Organization and Profile Provisioning

Status: Planned

Classification: S/B (domain ownership and event-flow redesign)

# Problem

Authz commits an organization and then synchronously asks Profile to create its
presentation row. If Profile fails, the RPC returns an error although the Authz
organization remains committed. Name/description are also stored in Authz while
Profile stores overlapping display/slug/description fields, and the services
form a dependency cycle.

# Evidence

- `internal/authz/grpc/org_create.go:createOrganization` calls
  `manager.CreateOrganization` before
  `profileClient.CreateOrganizationProfile`.
- `api/proto/profile/v1/organization.proto` documents
  `CreateOrganizationProfile` as a service-to-service call from Authz.
- `internal/profile/grpc/organization.go:CreateOrganizationProfile` persists
  the presentation row.
- `api/proto/authz/v1/admin.proto:CreateOrganizationRequest` contains name,
  description, slug, and owner; Authz policy storage also persists organization
  presentation fields.
- `internal/authz/app/bootstrap.go` dials Profile, while
  `internal/profile/app/bootstrap.go` dials Authz for immediate permission
  decisions, creating a synchronous Authz/Profile cycle.

# Current Design

Authz allocates and commits authorization state, then performs a second
non-transactional RPC. The caller cannot distinguish total failure from partial
success, and retry may conflict or duplicate presentation state.

# Why This Is a Problem

The API promises atomic-looking creation without a distributed transaction.
Overlapping fields have no clear authoritative owner, and the cycle complicates
startup, failure reasoning, and tests.

# Proposed Design

Authz owns organization identity/lifecycle, owner membership, and authorization
policy. Profile owns display name, slug, description, and visual presentation.
Authz commits the organization, initial owner membership/policy, and an
`OrganizationCreated` outbox event atomically. Profile consumes it idempotently
and creates its presentation row keyed by the supplied organization ID.

Authz stores only authorization-relevant organization state (ID, lifecycle
status, policy revision); remove duplicate presentation columns after backfill.
Profile-to-Authz synchronous authorization checks remain justified because an
update requires Authz's immediate authoritative permission result. Authz no
longer calls Profile.

Organization responses expose projection state explicitly:

- `PROVISIONING`: Authz organization exists but Profile has no completed
  projection yet;
- `READY`: Profile projection exists and its presentation is returned;
- `FAILED`: Profile recorded a terminal validation/uniqueness conflict and the
  response contains a stable failure code but no partial presentation.

The creation response is always `PROVISIONING`; it never races event consumption
to return a different initial state. Later gateway-services reads compose Authz
and Profile: missing projection means `PROVISIONING`, ready row means `READY`,
and a failure row means `FAILED`.

Slug allocation is deterministic and idempotent. Profile normalizes the event's
requested slug. If occupied by another organization, it appends `-` plus the
first 12 lowercase base32 characters of SHA-256(`organization_id`) after
truncating the base to the maximum length. The projection is keyed by
`organization_id` and records `creation_event_id`; replaying that event is a
no-op. A different creation event for the same organization, an invalid slug,
or the deterministic candidate colliding with another organization records
`FAILED` with `EVENT_CONFLICT`, `INVALID_SLUG`, or `SLUG_CONFLICT` respectively;
there is no random retry.

# Proposed API / Protocol Changes

- Remove `OrganizationProfileService.CreateOrganizationProfile`.
- `CreateOrganization` accepts the desired initial presentation fields. Authz
  validates them for event publication but stores them only in the transactional
  outbox payload; Profile becomes authoritative when it consumes the event.
- Publish `OrganizationCreated` with stable event/organization IDs and initial
  presentation; add `OrganizationDeleted`/`Disabled` facts when lifecycle
  behavior exists.
- `OrganizationGatewayService.GetOrganization` and `CreateOrganization` return
  `presentation_state`, optional ready presentation, and optional stable
  projection failure code.
- Add workload/admin-only
  `ProfileProvisioningService.RepairOrganizationProfile{organization_id,
  repair_id, requested_slug}`. It verifies the Authz organization, is idempotent
  by `repair_id`, transitions `FAILED -> PROVISIONING`, applies the same
  deterministic allocation, and ends in `READY` or `FAILED`. It cannot create an
  organization absent from Authz.

# Dependency / Flow Changes

Current: `Gateway -> Authz commit -> Profile RPC`, plus `Profile -> Authz`.

Target: `Gateway -> Authz commit+outbox -> response`; asynchronously
`Authz event -> Profile projection`. The only synchronous cross-edge is
`Profile -> Authz` for current authorization decisions.

# Security Implications

Only Authz can establish an organization and owner membership. Profile validates
that lifecycle events come from Authz and cannot grant membership. Duplicate or
forged events must not overwrite a newer presentation state. Failure responses
must not leak raw storage errors or conflicting organization IDs.

# Affected Code

- `api/proto/authz/v1/{admin.proto,organization.proto}` as applicable
- `api/proto/profile/v1/organization.proto`
- `internal/authz/grpc/org_create.go`, Authz policy/Ent schema and bootstrap
- `internal/profile/grpc/organization.go`, Profile core/Ent schema and consumer
- gateway organization mutations, events, generated code, migrations, tests

# Implementation Steps

1. Establish event/outbox and authenticated service identity prerequisites.
2. Define the sole owner for each organization field and migration mapping.
3. Commit Authz authorization state and outbox record in one transaction.
4. Add Profile's idempotent organization-event consumer.
5. Implement deterministic slug allocation, projection states, and the
   idempotent repair operation.
6. Migrate/backfill presentation data and remove Authz duplicate columns.
7. Remove Authz's Profile client and `CreateOrganizationProfile` RPC.
8. Preserve and explicitly test Profile's immediate Authz permission checks.

# Validation Criteria

- Profile outage does not change a committed organization response into an
  ambiguous failure.
- Duplicate/lost-delivery tests converge to one organization profile.
- Creation always returns PROVISIONING; reads and repair cover every documented
  state and stable failure code.
- Duplicate event/repair IDs are no-ops; different event IDs for one organization
  fail without overwriting presentation.
- Slug collision tests produce the same candidate across retries/processes, and
  terminal collision is repairable with a new requested slug.
- Authz contains no presentation state and has no Profile RPC dependency.
- Unauthorized Profile updates continue to fail from Authz's current decision.
- Searches find no `CreateOrganizationProfile` path or circular Authz-to-Profile
  connection.
