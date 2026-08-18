# Event registry

This registry is the checked-in inventory of NATS subjects. It records the
production state observed in this repository, rather than treating a topic
constant as proof that an event flow is deployed.

`Reliable` means JetStream-backed publish and durable acknowledgement where a
consumer is registered. Reliable subjects use file storage with a seven-day
limits-retention stream and a ten-minute transport de-duplication window.
Application consumers still need inbox idempotency. `Best effort` is a core
NATS publish or subscription with no retained repair path.

| Subject | Owner | Actual production producer | Actual live consumer(s) | Commit point | Delivery | Retention / repair | Dedup key | State |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `account.registered` | Authn | None | None | Planned Authn transactional outbox, in the account-registration transaction | Planned reliable, durable Profile inbox | Planned outbox relay; Profile inbox repair | `AccountRegistered.event_id` | **ADDITIVE — NOT ACTIVE** until the Authn outbox and Profile inbox are deployed |
| `organization.created` | Authz | None | None | Planned Authz transactional outbox, in the organization-creation transaction | Planned reliable, durable Profile inbox | Planned outbox relay; Profile inbox repair | `OrganizationCreated.event_id` | **ADDITIVE — NOT ACTIVE** until the Authz outbox and Profile inbox are deployed |
| `auth.started` | Authn | None | None | — | — | — | — | Dead constant |
| `auth.failed` | Authn | None | None | — | — | — | — | Dead constant |
| `auth.completed` | Authn | None | None | — | — | — | — | Dead constant |
| `auth.session.created` | Authn | None | None | — | — | — | — | Dead constant |
| `auth.session.revoked` | Authn | None | None | — | — | — | — | Dead constant |
| `auth.refresh_token.created` | Authn | None | None | — | — | — | — | Dead constant |
| `auth.refresh_token.rotated` | Authn | None | None | — | — | — | — | Dead constant |
| `auth.refresh_token.revoked` | Authn | None | None | — | — | — | — | Dead constant |
| `auth.refresh_token.expired` | Authn | None | None | — | — | — | — | Dead constant |
| `auth.refresh_token.reused` | Authn | None | None | — | — | — | — | Dead constant |
| `authz.policy.changed` | Authz | `internal/authz/policy.Manager.publishChange` | Authz replicas (`StartReplicaSync`); `pkg/authzclient.Enforcer` | After committed policy mutation | Reliable publish; ephemeral consumers | Seven-day JetStream storage; no consumer replay; periodic `LoadPolicy` repair | None; consumers reload authoritative policy | Live |
| `profile.change` | Profile | `internal/profile/core.Manager.publishProfileChanged` | None | After committed profile mutation | Reliable publish; no consumer | Seven-day JetStream retention; no application repair consumer | None; transport window only | Producer only |
| `mail.send.otp` | Authn | `internal/identity/method.EmailOTPMethod.generateAndSendOTP` | Mailer OTP handler | After OTP state is stored; not coupled to an account transaction | Reliable, durable `mailer_mail_send_otp` | Seven-day JetStream retention; critical retry then terminal delivery | None; transport window only | Live |
| `mail.send.login_alert` | Authn | `internal/authn/grpc.GRPCHandler.notifyLoginCompleted` | Mailer login-alert handler | After login completion; best-effort notification | Reliable, durable `mailer_mail_send_login_alert` | Seven-day JetStream retention; critical retry then terminal delivery | None; transport window only | Live |
| `mail.send.account_linked` | Authn | `internal/authn/grpc.GRPCHandler.notifyAccountLinked` | Mailer account-linked handler | After successful account-link operation | Reliable, durable `mailer_mail_send_account_linked` | Seven-day JetStream retention; critical retry then terminal delivery | None; transport window only | Live |
| `mail.send.account_unlinked` | Authn | `internal/authn/grpc.GRPCHandler.notifyAccountUnlinked` | None — handler exists but is not registered | After successful account-unlink operation | Reliable publish; no live consumer | Seven-day JetStream retention; no registered-consumer repair | None; transport window only | Producer only |
| `mail.send.email_changed` | Authn | None in production; test publisher only | Mailer email-changed handler | — | Reliable, durable `mailer_mail_send_email_changed` | Seven-day JetStream retention; critical retry then terminal delivery if produced | None; transport window only | Consumer only |
| `mail.send.passkey_added` | Authn | None in production; notifier has zero production callers | Mailer passkey-added handler | — | Reliable, durable `mailer_mail_send_passkey_added` | Seven-day JetStream retention; critical retry then terminal delivery if produced | None; transport window only | Consumer only |
| `mail.send.email` | Mailer | None | None | — | — | — | — | Dead constant |
| `mail.send.passkey_removed` | Authn | None | None | — | — | — | — | Dead constant |
| `mail.oidc.client_granted` | Authn | None | None | — | — | — | — | Dead constant |

The `account.registered` and `organization.created` messages are lifecycle
facts, not commands. Their UUID event IDs are the required future outbox and
inbox idempotency keys; adding the contracts and topic constants does not
activate a producer or consumer.
