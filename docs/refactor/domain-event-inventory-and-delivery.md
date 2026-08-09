# Domain Event Inventory and Delivery

Status: Planned

Classification: S/B (protocol cleanup and reliable delivery behavior)

# Problem

The event catalog includes broad or apparently unused contracts, while new
account and organization lifecycle propagation needs reliable publication and
idempotent consumption. Publication is not uniformly tied to the authoritative
database commit.

# Evidence

- `api/proto/event/v1/profile.proto` defines `ProfileChangedEvent` with a broad
  `IdentityInformation changes` payload and documents topic `profile.change`.
- `internal/profile/core/events.go` marshals and publishes profile changes, but
  the audit found no production consumer requiring that broad contract.
- Auth/session/email/passkey topic constants and message definitions exist
  across `api/proto/event`, `pkg/shared`, and Authn/Mailer packages without a
  complete producer/consumer pair for every topic.
- Authz `policy.changed` is produced and consumed by `pkg/authzclient`; its
  revision check and periodic reload provide eventual repair and should remain.
- Account and organization creation currently use synchronous cross-service
  provisioning rather than committed-fact events.

# Current Design

Some domain mutations publish best-effort after persistence; some schemas have
no live consumer. Payloads reuse `IdentityInformation`, obscuring ownership and
disclosing fields unrelated to consumers.

# Why This Is a Problem

Dead contracts create false architecture. Best-effort publication can
permanently miss state propagation after a successful commit. Broad payloads
couple domains and make duplicate/retry semantics unclear.

# Proposed Design

Maintain an explicit event registry recording subject, owner, producer,
consumers, commit point, delivery expectation, retention, and deduplication key.
Delete events with no justified consumer. Use narrow completed-fact events.

For durable lifecycle propagation, add an outbox row in the same transaction as
the domain mutation. A relay publishes with stable `event_id`; consumers store
processed IDs or use an idempotent natural-key upsert. At minimum define:

```proto
message AccountRegistered {
  string event_id = 1;
  string user_id = 2;
  google.protobuf.Timestamp occurred_at = 3;
}

message OrganizationCreated {
  string event_id = 1;
  string organization_id = 2;
  string display_name = 3;
  string slug = 4;
  string description = 5;
  google.protobuf.Timestamp occurred_at = 6;
}
```

This refactor adds deletion/disable facts only for lifecycle operations that
already have a live consumer in the final event registry; it does not retain
speculative schemas. Keep `authz.policy.changed` best-effort because revisioned
periodic resync is its documented repair mechanism.

# Proposed API / Protocol Changes

- Replace broad `ProfileChangedEvent` with consumer-driven events or remove it.
- Add account/organization lifecycle event schemas and subject constants.
- Every durable event carries `event_id`, aggregate ID, occurred time, and only
  fields required to initialize the consumer-owned projection.

# Dependency / Flow Changes

`domain transaction -> aggregate + outbox commit -> relay -> NATS -> idempotent
consumer -> consumer-owned projection`. No producer waits for consumer success.

# Security Implications

Workloads must authenticate to NATS with publish/subscribe ACLs per subject.
Consumers validate protobuf messages and reject invalid IDs. Narrow payloads
reduce sensitive-data exposure; duplicate delivery must not repeat privileged
state transitions.

# Affected Code

- `api/proto/event/v1/**`
- event subject/constants packages under `pkg/shared`
- Authn/Authz persistence schemas and outbox relays
- Profile consumers and processed-event storage
- existing Profile/Authn/Mailer publishers/consumers and tests

# Implementation Steps

1. Build and commit the event registry from actual producers/consumers.
2. Remove unjustified event schemas, constants, publishers, and dead consumers.
3. Define narrow lifecycle events and generate code.
4. Add reusable outbox mechanics without hiding domain event construction.
5. Add Authn/Authz transactional outbox writes and relay lifecycle.
6. Add idempotent Profile consumers with poison-message handling.
7. Configure subject ACLs and operational lag/failure metrics.

# Validation Criteria

- Every retained subject has exactly one authoritative owner and documented live
  producers/consumers.
- Kill-after-commit tests prove relay retry eventually publishes.
- Duplicate and reordered delivery tests do not create duplicate projections or
  regress state.
- No event carries `IdentityInformation` unless every field is owned by the
  producer and required by a consumer.
- `authz.policy.changed` revision/resync tests continue to pass.
