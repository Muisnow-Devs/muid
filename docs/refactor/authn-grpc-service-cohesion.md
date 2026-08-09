# Authn gRPC Service Cohesion

Status: Planned

Classification: S (focused service boundaries within one binary)

# Problem

`AuthnService` mixes authentication transitions, private account/identity
lookup, session verification and mutation, federated-identity revocation,
access-token issuance, and public key discovery. Callers depend on a large
client interface and overlapping session resolution RPCs whose intent is
difficult to distinguish.

# Evidence

- `api/proto/authn/v1/authn.proto:AuthnService` includes
  `StartAuthSession`, `ContinueAuthSession`, `RevokeFederatedIdentity`,
  `GetAuthorizedSession`, `GetAuthenticatedPrincipal`, `RevokeSession`,
  `ExtendSession`, `IssueAccessToken`, and `GetPublicKeys`.
- `internal/authn/grpc` implements these responsibilities through different
  managers but registers them as one generated service.
- gateway-public uses flow/session/token/key subsets; gateway-services uses
  principal/key behavior; tests must implement broad
  `AuthnServiceClient` fakes for narrow needs.
- `api/proto/authn/v1/oidc.proto` already demonstrates that several focused gRPC
  services can live in the same Authn binary.

# Current Design

Binary ownership is correct—Authn owns all listed state—but protocol cohesion is
not. Broad clients and two session-resolution methods encourage accidental use
of more privileged responses than a caller requires.

# Why This Is a Problem

Binary and service boundaries are conflated. Authorization policy, credential
handling, and error semantics differ across these operations, so one interface
does not communicate who may call which method or what side effects occur.

# Proposed Design

Keep one Authn deployable and split focused gRPC services:

```proto
service AuthenticationFlowService {
  rpc StartLogin(StartLoginRequest) returns (StartLoginResponse);
  rpc ContinueLogin(ContinueLoginRequest) returns (ContinueLoginResponse);
  rpc ResendLoginOTP(ResendLoginOTPRequest) returns (ResendLoginOTPResponse);
}

service SessionService {
  rpc GetSessionPrincipal(GetSessionPrincipalRequest) returns (SessionPrincipal);
  rpc RefreshSession(RefreshSessionRequest) returns (RefreshSessionResponse);
  rpc RevokeSession(RevokeSessionRequest) returns (RevokeSessionResponse);
  rpc IssueAccessToken(IssueAccessTokenRequest) returns (IssueAccessTokenResponse);
}

service LinkedIdentityService {
  rpc RevokeLinkedIdentity(RevokeLinkedIdentityRequest) returns (RevokeLinkedIdentityResponse);
}

service AccountService {
  rpc GetMyAccount(GetMyAccountRequest) returns (GetMyAccountResponse);
}

service SigningKeyService {
  rpc GetPublicKeys(GetPublicKeysRequest) returns (GetPublicKeysResponse);
}
```

Use existing OIDC services for OIDC responsibilities. Merge/remove
`GetAuthorizedSession` and `GetAuthenticatedPrincipal` after mapping actual
callers to one minimal `SessionPrincipal`; do not return opaque credentials or
token material unless that RPC explicitly issues/rotates them.

`GetMyAccountRequest` is empty: the subject comes only from a verified delegated
principal. `GetMyAccountResponse.account` contains exactly:

- `user_id`;
- `primary_email` and `primary_email_verified`;
- `account_status` (`ACTIVE`, `DISABLED`, or `PENDING_DELETION`);
- `created_at`;
- repeated `LinkedIdentitySummary { provider, linked_at }` without provider
  subject, provider tokens, raw claims, or credential identifiers.

Caller policy requires an allowed gateway-services workload identity, a valid
delegation with `aud=authn-account`, and delegation subject equal to the account
being read. Gateway-public cannot call AccountService directly.

# Proposed API / Protocol Changes

Rename methods/messages for observable domain intent, assign exact authorization
policy per service, and remove `AuthnService` completely after caller migration.
Requests must avoid redundant user IDs when identity comes from a session or
delegated principal.

`UserGatewayService.GetMe` composes account and profile as follows:

1. AccountService is authoritative and called first. Its unauthenticated,
   disabled-account, or unavailable result fails the entire BFF RPC with the
   corresponding stable status.
2. Profile `READY` returns account plus `MyProfile`.
3. Profile NotFound after a registered account returns success with account and
   `profile_state=PROVISIONING`, no profile message, and a retry hint.
4. A transient Profile Unavailable/DeadlineExceeded returns success with account
   and `profile_state=TEMPORARILY_UNAVAILABLE`, no profile message, and a retry
   hint; it is logged/metriced as degraded composition.
5. Invalid/corrupt Profile data fails the RPC as Internal rather than returning
   untrusted partial fields.

The GraphQL adapter maps these states explicitly and never substitutes private
account claims into public profile fields.

# Dependency / Flow Changes

Deployable topology is unchanged. Callers depend only on the generated focused
client interface they use. Interceptors remain shared at the Authn server and
can apply additional per-service policy.

# Security Implications

Focused services make token-issuing, key-discovery, private-account, and
identity-mutation boundaries explicit. `SigningKeyService` may be
workload/public-read as required; AccountService is self-only through
gateway-services; session mutation and linked-identity operations require
appropriate session or delegated authority. Responses must not echo presented
bearer credentials or provider subjects/tokens.

# Affected Code

- `api/proto/authn/v1/authn.proto` and new focused proto files
- Authn gRPC handlers/registration and tests
- gateway-public/internal/services Authn client dependencies
- Profile/Authz callers if present, generated files, mocks, documentation

# Implementation Steps

1. Produce a caller/method matrix and establish the one session-principal plus
   exact self-account responses above.
2. Add focused proto definitions and structurally move handlers without behavior
   changes.
3. Apply explicit per-service authentication/authorization policy.
4. Migrate each caller to its narrow client.
5. Remove duplicate session methods, obsolete messages, and `AuthnService`.
6. Split tests/fakes by focused interface and regenerate deterministically.

# Validation Criteria

- No generated or handwritten `AuthnService` reference remains.
- Every former method has either one justified focused replacement or is
  deleted with no caller.
- Session principal responses contain only caller-required claims and no echoed
  credential.
- `GetMyAccount` accepts no user ID, enforces subject equality, and exposes only
  the enumerated private claims.
- BFF tests cover READY, PROVISIONING, TEMPORARILY_UNAVAILABLE, disabled account,
  Authn outage, and corrupt Profile results with the specified semantics.
- No new binary or persistence boundary is introduced.
- Protocol generation, Authn tests, gateway tests, and full build pass.
