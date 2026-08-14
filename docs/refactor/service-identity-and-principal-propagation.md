# Service Identity and Principal Propagation

Status: Implemented

Classification: S/B (protocol and trust-boundary redesign)

# Problem

Backend services accept `x-user-id` over plaintext gRPC and cannot prove which
workload asserted it. The services gateway's current mTLS verifies a CA chain
but does not bind the peer to one recognized workload identity.

# Evidence

- `internal/gatewaypublic/app/bootstrap.go`,
  `internal/gatewayinternal/app/bootstrap.go`, and
  `internal/gatewayservices/app/bootstrap.go` call
  `grpcutils.DialInsecureClient` for backend connections.
- `internal/authz/grpc/identity_interceptor.go` treats `x-user-id` as the caller
  identity without an authenticated workload.
- `internal/gatewaypublic/reqctx/reqctx.go`,
  `internal/gatewayservices/grpc/handler.go`, and
  `internal/gatewayinternal/app/admin.go` write that metadata.
- `internal/profile/grpc/request_ctx.go` has separate request/user parsing rules.
- `pkg/gateway/mtls` verifies certificates but does not enforce one recognized
  SPIFFE URI SAN per peer.

# Current Design

Gateways authenticate users and assert UUID metadata, but backend transport and
caller workload are not authenticated. Network placement is the effective trust
boundary. Identity parsing is duplicated and method authorization is implicit.

# Why This Is a Problem

Any process that reaches a backend can impersonate any user. Broad CA trust can
admit an unrelated workload, duplicated parsing can disagree on malformed or
duplicate metadata, and service-only methods cannot prove that no user was
delegated.

# Proposed Design

Every internal gRPC connection uses mutual TLS. A workload certificate contains
exactly one recognized URI SAN:

`spiffe://muid/service/<workload>`

Recognized workload names are `gateway-public`, `gateway-services`,
`gateway-internal`, `authn`, `authz`, `profile`, and `admin-ingress`. Peer
verification requires a valid configured chain, clientAuth EKU for client
certificates, TLS 1.2 or newer, and exactly one recognized URI SAN. Client dials
perform normal DNS/IP server-name verification and never set
`InsecureSkipVerify`.

After TLS authentication, one shared interceptor constructs:

```go
type WorkloadID string

type RequestPrincipal struct {
    Workload WorkloadID
    UserID   uuid.UUID
    HasUser  bool
}
```

Each full gRPC method has an explicit allowed-workload set and one user mode:

- `UserForbidden`: reject every `x-user-id` value;
- `UserOptional`: accept zero or one canonical non-zero UUID;
- `UserRequired`: require exactly one canonical non-zero UUID.

All modes reject duplicate, malformed, whitespace-padded, or zero UUID values.
Handlers read only `grpcutils.RequestPrincipal` from context. Legacy service
interceptors and request-ID-derived identity are removed.

## TLS configuration groups

Envconfig applies the normal process prefix to every field.

- Authn, Authz, and Profile inbound server group:
  `GRPC_TLS_CERT_PATH`, `GRPC_TLS_KEY_PATH`, `GRPC_MTLS_CLIENT_CA_PATH`.
- Authn, Authz, and Profile outbound client group:
  `GRPC_CLIENT_CERT_PATH`, `GRPC_CLIENT_KEY_PATH`, `GRPC_ROOT_CA_PATH`.
- Gateway Public uses the outbound client group only.
- Gateway Services uses the outbound client group and retains ingress
  `MTLS_CLIENT_CA_PATH`, `TLS_CERT_PATH`, `TLS_KEY_PATH`.
- Gateway Internal uses the outbound client group plus ingress
  `MTLS_CLIENT_CA_PATH`, `TLS_CERT_PATH`, `TLS_KEY_PATH`.

A partial group fails validation in every mode. Every applicable group is
required in every mode because a plaintext debug connection cannot prove its
workload identity or safely enforce the method matrix. Configuring an optional
downstream address still requires the outbound client group. Certificate, key,
and CA material is parsed at startup.

## Service authorization matrix

| Server/API | Allowed workloads | User mode / additional policy |
| --- | --- | --- |
| Authn authentication flows | `gateway-public` | Forbidden |
| Authn public/signing keys | `gateway-public`, `gateway-services`, `gateway-internal` | Forbidden |
| Authn OIDC service | `gateway-public` | Forbidden |
| Authn OIDC admin | `gateway-internal` | Required; platform permission and existing organization permission both required |
| Authz public user/organization APIs | `gateway-public` | Required |
| Authz internal authorization APIs | `authn`, `profile` | Forbidden |
| Authz platform permission check | `gateway-internal`, plus Authn for OIDC-admin backend recheck | Forbidden on transport; target user is an explicit validated request field |
| Authz admin | `gateway-internal` | Required; matching platform permission required |
| Profile create user profile | `authn` | Forbidden |
| Profile get profile | `authn`, `gateway-public`, `gateway-services` | Authn: Forbidden; gateways: Optional or Required according to the existing public/self method semantics, made explicit per full method |
| Profile user update/avatar APIs | `gateway-public` | Required |
| Profile create organization profile | `authz` | Forbidden |
| Profile organization get/update | `gateway-public` | Required |

Methods not present in the matrix fail closed until assigned a policy.

# Proposed API / Protocol Changes

- Move the general mTLS package from `pkg/gateway/mtls` to `pkg/mtls`.
- Add shared TLS server/client constructors and a TLS gRPC dialer under
  `pkg/grpc_utils`.
- Add `WorkloadID`, `RequestPrincipal`, context accessors, `UserMode`, and a
  method authorization table/interceptor under `pkg/grpc_utils`.
- Retain `x-user-id` only as the internal delegated-user transport field; it has
  no authority without an allowed mTLS workload and method policy.
- Add Authz platform policy and RPC described in the administrator record.

# Dependency / Flow Changes

`verified client credential -> gateway user authentication -> mTLS backend dial
with SPIFFE workload -> method workload policy -> strict x-user-id parsing ->
typed RequestPrincipal -> domain authorization`.

Service-only flows omit user metadata and are rejected if it is present.

# Security Implications

Finding classification: `Architectural Security Risk`.

- Threat: user impersonation, metadata spoofing, or internal confused deputy.
- Precondition: backend reachability, compromised unrelated workload, or broad
  certificate issuance.
- Impact: profile/account/authorization operations as another user.
- Existing protection: edge JWT checks and network placement.
- Insufficiency: neither authenticates the backend caller nor constrains which
  workload may assert a user on a method.
- Correction: strict workload mTLS, typed principal parsing, and fail-closed
  per-method workload/user policy.

# Affected Code

- `pkg/gateway/mtls`, new `pkg/mtls`, and `pkg/grpc_utils`
- Authn/Authz/Profile app config, bootstrap, server, and identity interceptors
- all three gateway config/bootstrap/client paths
- `pkg/gateway/httpmeta` and gateway request-context/handler metadata writers
- Authz policy schema/RPC/client from the administrator record
- deployment certificates, environment configuration, tests, and documentation

# Implementation Steps

The following rows are atomic merge/validation units. Do not leave a row half
cut over.

1. Add characterization tests for current caller/user behavior and every RPC
   family in the authorization matrix.
2. Move `pkg/gateway/mtls` to `pkg/mtls` and update imports without behavior
   change.
3. Add strict TLS server/client loaders and the verified TLS gRPC dialer,
   including SPIFFE SAN parsing and startup config validation.
4. Add typed `RequestPrincipal`, user modes, and the fail-closed method policy
   interceptor.
5. Consolidate Authz/Profile identity parsing onto the shared principal and
   remove duplicate/lenient parsers.
6. Add Authz static `platform_roles` and `platform_bindings` policy loading.
7. Add `CheckPlatformPermission` protocol, Authz implementation, and typed
   client used by Gateway Internal and Authn admin authorization.
8. Cut over Authz public, internal, platform-check, and admin listeners to mTLS
   and the complete method matrix.
9. Cut over Authn inbound listeners and outbound Authz client; preserve forbidden
   user mode on service-only calls.
10. Cut over Profile inbound listeners and outbound Authz client in parallel
    with row 9 only after shared prerequisites pass.
11. Cut over Gateway Public outbound clients and strict delegated-user metadata.
12. Cut over Gateway Services ingress identity plus outbound clients.
13. Cut over Gateway Internal `admin-ingress` mTLS, outbound clients, and replace
    the UUID allowlist with Authz platform permission checks.
14. Remove insecure dial/server paths and obsolete identity interceptors, then
    run end-to-end rollout validation and update deployment/engineering docs.

# Validation Criteria

- Certificate tests reject plaintext, unknown CA, TLS below 1.2, wrong/missing/
  multiple/unrecognized URI SANs, wrong client EKU, and DNS/IP name mismatch.
- No code uses `InsecureSkipVerify`; no mode has a plaintext or incomplete
  TLS-group fallback.
- Matrix tests cover every full method, allowed and denied workload, and its
  forbidden/optional/required user mode.
- Duplicate, malformed, padded, zero, missing-required, and present-forbidden
  `x-user-id` values fail before handlers.
- Service-only Authn/Authz/Profile calls succeed only without user metadata.
- Admin end-to-end tests cover platform permission and OIDC dual authorization.
- Searches find no gateway/backend `DialInsecureClient`, legacy identity
  interceptor, or unclassified RPC.
- Coordinated production rollout proves all certificates/config are present
  before plaintext paths are removed.
- `make check`, full tests, affected `-race` suites, vet, build, Buf/generation
  checks, and root/API vulnerability scans pass.

# Implemented Result

All seven workload identities now use strict mTLS and an exact per-method
workload/user policy. Authn, Authz, and Profile require inbound and outbound
TLS groups in every mode; the three gateways require their applicable ingress
and outbound groups. The shared interceptor is the only parser for delegated
`x-user-id`, and handlers consume the typed request principal. Plaintext dials,
optional TLS server branches, the Authz metadata identity interceptor, and the
Profile metadata parser were removed.

Certificate loader/handshake tests use verified roots and names without a TLS
verification bypass. Principal tests cover the recognized SPIFFE identities,
verified-chain requirement, exact URI SAN shape, per-workload user modes, and
malformed/duplicate/zero metadata. Per-service policy tests enumerate the full
registered method matrices. The final cleanup passed 168 focused tests under
the race detector, focused vet, and 919 repository tests across 148 packages;
stale-path searches found no plaintext dial, legacy identity interceptor, or
metadata-derived handler identity.
