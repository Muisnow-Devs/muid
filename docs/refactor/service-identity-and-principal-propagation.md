# Service Identity and Principal Propagation

Status: Planned

Classification: S/B (protocol and trust-boundary redesign)

# Problem

Backend services accept a caller-controlled-shaped `x-user-id` string over
plaintext gRPC connections. They cannot cryptographically distinguish a trusted
gateway from another reachable client. The services gateway's optional mTLS
accepts any certificate chaining to its CA without binding an expected workload
identity.

# Evidence

- Gateway bootstrap files call `grpcutils.DialInsecureClient` for Authn, Authz,
  and Profile connections:
  `internal/gatewaypublic/app/bootstrap.go`,
  `internal/gatewayinternal/app/bootstrap.go`, and
  `internal/gatewayservices/app/bootstrap.go`.
- `internal/authz/grpc/identity_interceptor.go` defines
  `UserIDMetadataKey = "x-user-id"` and installs it in context.
- `internal/gatewaypublic/reqctx/reqctx.go`,
  `internal/gatewayservices/grpc/handler.go`, and
  `internal/gatewayinternal/app/admin.go` append that metadata.
- `internal/profile/grpc/request_ctx.go` derives request identity from metadata
  and, for some methods, request IDs.
- `internal/gatewayservices/app/config.go` exposes a client CA/cert/key trio;
  `pkg/gateway/mtls` verifies chains but does not define an expected SAN/SPIFFE
  identity policy.
- Authz and Profile listeners are separately reachable processes and cannot
  prove that metadata originated at the intended gateway.

# Current Design

Edge gateways authenticate bearer tokens, then assert a UUID in metadata.
Backend channels are insecure. Network placement is the effective protection.
For the services BFF, possession of any CA-issued client certificate is treated
as sufficient client identity.

# Why This Is a Problem

Any process that can reach a backend can impersonate any user. A compromised
workload can become a confused deputy, and an on-path actor can observe or alter
RPC traffic. A broad client CA also makes unrelated certificate holders valid
BFF clients.

# Proposed Design

Use workload mTLS on every gateway-to-backend and service-to-service connection.
Authorize the peer identity from an exact URI SAN (prefer SPIFFE-style IDs) or
explicit DNS SAN policy per listener. Carry delegated user identity in a signed,
short-lived `DelegatedPrincipal` credential bound to issuer, audience, workload,
subject, authentication time/level, expiry, and unique ID. Backend interceptors
verify both TLS peer and delegated credential, strip external identity metadata,
and place a typed principal in context.

For direct service calls without a user, use typed workload identity only.
Admin calls additionally require the authority described in the internal-admin
plan. Do not let services mint arbitrary delegated users merely because they
hold a workload certificate.

# Proposed API / Protocol Changes

Define an internal authentication contract, for example:

```proto
message DelegatedPrincipal {
  string user_id = 1;
  string issuer = 2;
  string audience = 3;
  string gateway_id = 4;
  google.protobuf.Timestamp authenticated_at = 5;
  google.protobuf.Timestamp expires_at = 6;
  string token_id = 7;
  repeated string authentication_methods = 8;
}
```

Wrap the serialized message in `SignedDelegatedPrincipal { bytes payload,
string key_id, bytes ed25519_signature }` and transmit it only in the binary
gRPC metadata key `muid-delegated-principal-bin`. Backend configuration trusts
explicit gateway public keys by key ID and audience. Remove `x-user-id`
authentication. Keep non-security trace/client metadata separate.

# Dependency / Flow Changes

`client credential -> gateway verification -> signed delegated principal ->
mTLS backend channel -> peer authorization + delegation verification -> typed
request context -> domain authorization`.

# Security Implications

Finding classification: `Architectural Security Risk`.

- Threat: user impersonation, metadata tampering, internal confused deputy.
- Precondition: backend reachability, compromised workload, or broad CA access.
- Impact: profile data access/mutation and authorization operations as any user.
- Existing protection: gateway JWT checks and network assumptions.
- Insufficiency: neither authenticates the backend caller or protects metadata.
- Correction: mutually authenticated transport plus audience/workload-bound
  delegation and per-listener peer policy.

# Affected Code

- `pkg/grpcutils` dial/server credential helpers
- `pkg/gateway/mtls`, gateway config/bootstrap packages
- Authn/Authz/Profile app listener configuration and interceptors
- `pkg/gateway/httpmeta`, gateway request-context/handler packages
- deployment certificates/secrets and end-to-end tests

# Implementation Steps

1. Inventory each listener and assign allowed workload URI SANs and delegation
   audiences.
2. Add shared TLS client/server configuration with exact peer authorization.
3. Define delegated-principal signing, verification, rotation, expiry, and replay
   expectations.
4. Install verification interceptors before request-context and authorization
   interceptors.
5. Migrate gateways and legitimate service clients one listener at a time.
6. Remove insecure dials and raw identity metadata readers/writers.
7. Restrict network policies as an independent supporting control.

# Validation Criteria

- Plaintext, unknown CA, wrong SAN, wrong audience, expired, altered, and
  unauthorized-workload delegations fail before handlers.
- A trusted workload without a delegated user cannot impersonate one.
- Direct service operations use workload identity and do not require fake user
  metadata.
- Searches find no security use of `x-user-id` or gateway backend
  `DialInsecureClient`.
- Integration tests cover certificate rotation and valid delegated calls.
