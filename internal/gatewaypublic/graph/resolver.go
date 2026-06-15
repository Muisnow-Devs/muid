package graph

// This file is not regenerated. It holds the resolver root (dependency
// injection), the session/access-token cookie helpers, the caller-identity
// resolution for the data plane, and the proto→GraphQL mapping helpers.

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/vektah/gqlparser/v2/gqlerror"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	authnpb "sanzi.io/muid/api/proto/authn/v1"
	basicpb "sanzi.io/muid/api/proto/authn/v1/basic"
	challengepb "sanzi.io/muid/api/proto/authn/v1/challenge"
	proofpb "sanzi.io/muid/api/proto/authn/v1/proof"
	sessionpb "sanzi.io/muid/api/proto/authn/v1/session"
	authzpb "sanzi.io/muid/api/proto/authz/v1"
	profilepb "sanzi.io/muid/api/proto/profile/v1"
	claimspb "sanzi.io/muid/api/proto/shared/v1/claims"
	"sanzi.io/muid/infra/turnstile"
	"sanzi.io/muid/internal/gatewaypublic/graph/loader"
	"sanzi.io/muid/internal/gatewaypublic/graph/model"
	"sanzi.io/muid/internal/gatewaypublic/reqctx"
	"sanzi.io/muid/pkg/gateway/jwtauth"
)

const defaultSessionCookieName = "__Host-muid_session"

// ErrNoSessionCookie signals that no session cookie was presented, so the caller
// is unauthenticated. Surfaced as "authentication required" (GraphQL) or 401 (REST).
var ErrNoSessionCookie = errors.New("graph: no session cookie")

// AuthFailureRecorder records a failed authentication attempt for an identifier
// (client IP) so the risk model can detect brute-force activity. Implemented by
// risk.Tracker.
type AuthFailureRecorder interface {
	RecordAuthFailure(ctx context.Context, identifier string) error
}

// TokenVerifier verifies a session access-token JWT and returns its claims.
// Implemented by *jwtauth.Verifier (and faked in tests).
type TokenVerifier interface {
	Verify(ctx context.Context, raw string) (jwtauth.Claims, error)
}

// SessionCookie configures the httpOnly cookie carrying the opaque session token
// (host-locked to the gateway origin).
type SessionCookie struct {
	Name     string
	Secure   bool
	SameSite http.SameSite
}

// AccessTokenCookie configures the httpOnly cookie carrying the short-lived
// access-token JWT. It is subdomain-scoped (a parent Domain may be set), so it
// uses the __Secure- prefix rather than __Host-.
type AccessTokenCookie struct {
	Name     string
	Domain   string
	Secure   bool
	SameSite http.SameSite
}

// Resolver is the GraphQL root resolver and dependency holder for the public
// gateway's app-facing API and the authz/profile BFF data plane.
type Resolver struct {
	Authn      authnpb.AuthnServiceClient
	AuthzUser  authzpb.AuthzUserServiceClient
	AuthzOrg   authzpb.AuthzOrganizationAdminServiceClient
	Profile    profilepb.ProfileServiceClient
	OrgProfile profilepb.OrganizationProfileServiceClient
	Verifier   TokenVerifier
	Turnstile  turnstile.Verifier
	Failures   AuthFailureRecorder

	SessionCookieCfg SessionCookie
	AccessCookieCfg  AccessTokenCookie
}

func (r *Resolver) sessionCookieName() string {
	if r.SessionCookieCfg.Name != "" {
		return r.SessionCookieCfg.Name
	}
	return defaultSessionCookieName
}

func (r *Resolver) accessCookieName() string {
	if r.AccessCookieCfg.Name != "" {
		return r.AccessCookieCfg.Name
	}
	return "__Secure-muid_at"
}

func sameSiteOrLax(s http.SameSite) http.SameSite {
	if s != 0 {
		return s
	}
	return http.SameSiteLaxMode
}

func cookieValue(ctx context.Context, name string) string {
	txn, ok := reqctx.HTTPFromContext(ctx)
	if !ok {
		return ""
	}
	c, err := txn.R.Cookie(name)
	if err != nil {
		return ""
	}
	return c.Value
}

func (r *Resolver) sessionTokenFromCookie(ctx context.Context) string {
	return cookieValue(ctx, r.sessionCookieName())
}

// outgoing builds the downstream gRPC context for authn calls: client IP/geo
// metadata plus the session-token authorization header when a session cookie is
// present (login flows have none, which is fine).
func (r *Resolver) outgoing(ctx context.Context) context.Context {
	return reqctx.OutgoingMetadataWithSession(ctx, r.sessionTokenFromCookie(ctx))
}

func (r *Resolver) accessTokenFromCookie(ctx context.Context) string {
	return cookieValue(ctx, r.accessCookieName())
}

func (r *Resolver) setSessionCookie(ctx context.Context, token string) {
	txn, ok := reqctx.HTTPFromContext(ctx)
	if !ok || token == "" {
		return
	}
	http.SetCookie(txn.W, &http.Cookie{
		Name:     r.sessionCookieName(),
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.SessionCookieCfg.Secure,
		SameSite: sameSiteOrLax(r.SessionCookieCfg.SameSite),
	})
}

func (r *Resolver) clearSessionCookie(ctx context.Context) {
	txn, ok := reqctx.HTTPFromContext(ctx)
	if !ok {
		return
	}
	http.SetCookie(txn.W, &http.Cookie{
		Name:     r.sessionCookieName(),
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   r.SessionCookieCfg.Secure,
		SameSite: sameSiteOrLax(r.SessionCookieCfg.SameSite),
		MaxAge:   -1,
	})
}

// setAccessTokenCookie writes the access-token JWT as a subdomain-scoped
// httpOnly cookie. expiresAt (when present) bounds the cookie lifetime.
func (r *Resolver) setAccessTokenCookie(ctx context.Context, token string, expiresAt *timestamppb.Timestamp) {
	txn, ok := reqctx.HTTPFromContext(ctx)
	if !ok || token == "" {
		return
	}
	c := &http.Cookie{
		Name:     r.accessCookieName(),
		Value:    token,
		Path:     "/",
		Domain:   r.AccessCookieCfg.Domain,
		HttpOnly: true,
		Secure:   r.AccessCookieCfg.Secure,
		SameSite: sameSiteOrLax(r.AccessCookieCfg.SameSite),
	}
	if expiresAt != nil {
		c.Expires = expiresAt.AsTime()
	}
	http.SetCookie(txn.W, c)
}

func (r *Resolver) clearAccessTokenCookie(ctx context.Context) {
	txn, ok := reqctx.HTTPFromContext(ctx)
	if !ok {
		return
	}
	http.SetCookie(txn.W, &http.Cookie{
		Name:     r.accessCookieName(),
		Value:    "",
		Path:     "/",
		Domain:   r.AccessCookieCfg.Domain,
		HttpOnly: true,
		Secure:   r.AccessCookieCfg.Secure,
		SameSite: sameSiteOrLax(r.AccessCookieCfg.SameSite),
		MaxAge:   -1,
	})
}

// MintAccessToken exchanges the session cookie for a fresh access-token JWT,
// sets the access-token cookie, and returns the verified claims. It is shared by
// the data-plane resolvers (lazy mint) and the POST /security/access-token route.
// Returns ErrNoSessionCookie when unauthenticated.
func (r *Resolver) MintAccessToken(ctx context.Context) (jwtauth.Claims, error) {
	if r.Verifier == nil {
		return jwtauth.Claims{}, gqlerror.Errorf("data plane not configured")
	}
	session := r.sessionTokenFromCookie(ctx)
	if session == "" {
		return jwtauth.Claims{}, ErrNoSessionCookie
	}
	resp, err := r.Authn.IssueAccessToken(reqctx.OutgoingMetadataWithSession(ctx, session), &authnpb.IssueAccessTokenRequest{})
	if err != nil {
		return jwtauth.Claims{}, mapAuthError(err)
	}
	at := resp.GetAccessToken()
	if at == nil || at.GetValue() == "" {
		return jwtauth.Claims{}, gqlerror.Errorf("access token unavailable")
	}
	claims, err := r.Verifier.Verify(ctx, at.GetValue())
	if err != nil {
		return jwtauth.Claims{}, gqlerror.Errorf("authentication failed")
	}
	r.setAccessTokenCookie(ctx, at.GetValue(), at.GetExpiresAt())
	return claims, nil
}

// callerMemo memoises the per-request caller resolution so that concurrently
// executing field resolvers (gqlgen runs sibling query fields in goroutines)
// resolve identity — and mint + write the access-token cookie — exactly once.
// Without this, each field would call MintAccessToken and race on the shared
// response writer's header map (a fatal "concurrent map writes").
type callerMemo struct {
	once   sync.Once
	userID uuid.UUID
	ctx    context.Context
	err    error
}

type callerMemoKey struct{}

// WithCaller installs a fresh per-request caller-auth memo. The public gateway's
// graphqlContext middleware seeds it before gqlgen dispatches field resolvers.
func WithCaller(ctx context.Context) context.Context {
	return context.WithValue(ctx, callerMemoKey{}, &callerMemo{})
}

func callerFromContext(ctx context.Context) (*callerMemo, bool) {
	m, ok := ctx.Value(callerMemoKey{}).(*callerMemo)
	return m, ok
}

// authed returns the verified caller id plus an outgoing ctx carrying it under
// the unified backend identity key. It resolves once per request via the memo
// installed by WithCaller; callers without a memo (e.g. unit tests) resolve
// directly.
func (r *Resolver) authed(ctx context.Context) (uuid.UUID, context.Context, error) {
	memo, ok := callerFromContext(ctx)
	if !ok {
		return r.resolveCaller(ctx)
	}
	memo.once.Do(func() {
		memo.userID, memo.ctx, memo.err = r.resolveCaller(ctx)
	})
	return memo.userID, memo.ctx, memo.err
}

// resolveCaller resolves the verified caller from the access-token cookie,
// minting a fresh one (and setting the cookie) from the session cookie on
// miss/expiry. It performs the single Set-Cookie write per request.
func (r *Resolver) resolveCaller(ctx context.Context) (uuid.UUID, context.Context, error) {
	if r.Verifier == nil {
		return uuid.Nil, ctx, gqlerror.Errorf("data plane not configured")
	}
	if raw := r.accessTokenFromCookie(ctx); raw != "" {
		if claims, err := r.Verifier.Verify(ctx, raw); err == nil {
			return claims.UserID, reqctx.OutgoingAuthenticated(ctx, claims.UserID.String()), nil
		}
	}
	claims, err := r.MintAccessToken(ctx)
	if err != nil {
		if errors.Is(err, ErrNoSessionCookie) {
			return uuid.Nil, ctx, gqlerror.Errorf("authentication required")
		}
		return uuid.Nil, ctx, err
	}
	return claims.UserID, reqctx.OutgoingAuthenticated(ctx, claims.UserID.String()), nil
}

// ---- auth-flow mappers (Phase 1) ----

func rfc3339(ts interface{ AsTime() time.Time }) *string {
	if ts == nil {
		return nil
	}
	s := ts.AsTime().UTC().Format(time.RFC3339)
	return &s
}

func authChallenge(ch *challengepb.AuthChallenge) *model.AuthChallenge {
	if ch == nil {
		return nil
	}
	out := &model.AuthChallenge{
		ChallengeID: ch.GetChallengeId(),
		Detail:      challengeDetail(ch),
	}
	if ts := ch.GetIssuedAt(); ts != nil {
		out.IssuedAt = rfc3339(ts)
	}
	if ts := ch.GetExpiresAt(); ts != nil {
		out.ExpiresAt = rfc3339(ts)
	}
	return out
}

func challengeDetail(ch *challengepb.AuthChallenge) model.AuthChallengeDetail {
	switch {
	case ch.HasEmailChallenge():
		ec := ch.GetEmailChallenge()
		return model.EmailChallenge{
			EmailMasked:          ec.GetEmailMasked(),
			ResendCooldownMillis: int(ec.GetResendCooldownMillis()),
		}
	case ch.HasOauthChallenge():
		oc := ch.GetOauthChallenge()
		return model.OAuthChallenge{Provider: oc.GetProvider(), AuthURL: oc.GetAuthUrl()}
	case ch.HasPasskeyChallenge():
		return passkeyDetail(ch.GetPasskeyChallenge())
	default:
		return nil
	}
}

func passkeyDetail(pc *challengepb.PasskeyChallenge) model.PasskeyChallenge {
	ceremony := mapCeremony(pc.GetCeremony())
	options := pc.GetPublicKeyCredentialRequestOptionsJson()
	if ceremony == model.PasskeyCeremonyRegistration {
		options = pc.GetPublicKeyCredentialCreationOptionsJson()
	}
	return model.PasskeyChallenge{
		State:         pc.GetState(),
		Ceremony:      ceremony,
		OptionsJSON:   options,
		TimeoutMillis: int(pc.GetTimeoutMillis()),
	}
}

func sessionFromResult(result *sessionpb.AuthenticatedResult) *model.Session {
	if result == nil {
		return nil
	}
	var userID *string
	if id := result.GetUserId(); id != "" {
		userID = &id
	}
	return sessionModel(userID, mapAuthLevel(result.GetAuthLevel()), result.GetSessionContext())
}

func sessionModel(userID *string, level *model.AuthLevel, sc *sessionpb.SessionContext) *model.Session {
	out := &model.Session{UserID: userID, AuthLevel: level}
	if sc == nil {
		return out
	}
	if ts := sc.GetExpiresAt(); ts != nil {
		out.ExpiresAt = rfc3339(ts)
	}
	return out
}

func mapStatus(s basicpb.AuthStatus) model.AuthStatus {
	switch s {
	case basicpb.AuthStatus_AUTH_STATUS_AUTHENTICATED:
		return model.AuthStatusAuthenticated
	case basicpb.AuthStatus_AUTH_STATUS_CHALLENGE_REQUIRED:
		return model.AuthStatusChallengeRequired
	default:
		return model.AuthStatusPending
	}
}

func mapAuthLevel(l sessionpb.AuthLevel) *model.AuthLevel {
	var v model.AuthLevel
	switch l {
	case sessionpb.AuthLevel_AUTH_LEVEL_LOW:
		v = model.AuthLevelLow
	case sessionpb.AuthLevel_AUTH_LEVEL_MEDIUM:
		v = model.AuthLevelMedium
	case sessionpb.AuthLevel_AUTH_LEVEL_HIGH:
		v = model.AuthLevelHigh
	default:
		return nil
	}
	return &v
}

func mapMethod(m model.AuthMethod) basicpb.AuthMethod {
	switch m {
	case model.AuthMethodEmailOtp:
		return basicpb.AuthMethod_AUTH_METHOD_EMAIL_OTP
	case model.AuthMethodUsernameOtp:
		return basicpb.AuthMethod_AUTH_METHOD_USERNAME_OTP
	case model.AuthMethodOauth:
		return basicpb.AuthMethod_AUTH_METHOD_OAUTH
	case model.AuthMethodPasskey:
		return basicpb.AuthMethod_AUTH_METHOD_PASSKEY
	default:
		return basicpb.AuthMethod_AUTH_METHOD_UNSPECIFIED
	}
}

func mapIntent(i *model.AuthIntent) basicpb.AuthIntent {
	if i == nil {
		return basicpb.AuthIntent_AUTH_INTENT_LOGIN
	}
	switch *i {
	case model.AuthIntentLinkAccount:
		return basicpb.AuthIntent_AUTH_INTENT_LINK_ACCOUNT
	case model.AuthIntentReauthenticate:
		return basicpb.AuthIntent_AUTH_INTENT_REAUTHENTICATE
	default:
		return basicpb.AuthIntent_AUTH_INTENT_LOGIN
	}
}

func mapCeremony(c challengepb.PasskeyCeremony) model.PasskeyCeremony {
	if c == challengepb.PasskeyCeremony_PASSKEY_CEREMONY_REGISTRATION {
		return model.PasskeyCeremonyRegistration
	}
	return model.PasskeyCeremonyAuthentication
}

// buildProof validates that exactly one proof variant is set and maps it onto
// the authn AuthProof oneof.
func buildProof(in *model.AuthProofInput) (*proofpb.AuthProof, error) {
	if in == nil {
		return nil, gqlerror.Errorf("a proof is required")
	}
	count := 0
	if in.Email != nil {
		count++
	}
	if in.Oauth != nil {
		count++
	}
	if in.Passkey != nil {
		count++
	}
	if count != 1 {
		return nil, gqlerror.Errorf("exactly one proof variant must be provided")
	}

	proof := &proofpb.AuthProof{}
	switch {
	case in.Email != nil:
		ep := &proofpb.EmailProof{}
		switch {
		case in.Email.Resend != nil && *in.Email.Resend:
			ep.SetResend(&proofpb.EmailResendOtp{})
		case in.Email.OtpCode != nil && *in.Email.OtpCode != "":
			ep.SetOtpCode(*in.Email.OtpCode)
		default:
			return nil, gqlerror.Errorf("email proof requires an otpCode or resend")
		}
		proof.SetEmailProof(ep)
	case in.Oauth != nil:
		op := &proofpb.OAuthProof{}
		op.SetCode(in.Oauth.Code)
		op.SetState(in.Oauth.State)
		proof.SetOauthProof(op)
	case in.Passkey != nil:
		pp := &proofpb.PasskeyProof{}
		switch {
		case in.Passkey.AssertionResponseJSON != nil && *in.Passkey.AssertionResponseJSON != "":
			pp.SetCredentialAssertionResponseJson(*in.Passkey.AssertionResponseJSON)
		case in.Passkey.CreationResponseJSON != nil && *in.Passkey.CreationResponseJSON != "":
			pp.SetCredentialCreationResponseJson(*in.Passkey.CreationResponseJSON)
		default:
			return nil, gqlerror.Errorf("passkey proof requires an assertion or creation response")
		}
		proof.SetPasskeyProof(pp)
	}
	return proof, nil
}

// recordAuthFailure bumps the per-IP failure counter feeding the risk model.
func (r *Resolver) recordAuthFailure(ctx context.Context) {
	if r.Failures == nil {
		return
	}
	if facts, ok := reqctx.FactsFromContext(ctx); ok && facts.ClientIP != "" {
		_ = r.Failures.RecordAuthFailure(ctx, facts.ClientIP)
	}
}

// mapAuthError converts an authn gRPC error into a client-safe GraphQL error,
// surfacing the structured AuthFailure code as the error extension "code".
func mapAuthError(err error) error {
	st, ok := status.FromError(err)
	if !ok {
		return gqlerror.Errorf("authentication error")
	}
	for _, detail := range st.Details() {
		f, ok := detail.(*sessionpb.AuthFailure)
		if !ok {
			continue
		}
		reason := f.GetReason()
		if reason == "" {
			reason = "authentication failed"
		}
		ge := gqlerror.Errorf("%s", reason)
		if code := authErrorCodeString(f.GetErrorCode()); code != "" {
			ge.Extensions = map[string]any{"code": code}
		}
		return ge
	}
	switch st.Code() {
	case codes.InvalidArgument:
		return gqlerror.Errorf("invalid request")
	case codes.ResourceExhausted:
		return gqlerror.Errorf("too many attempts, please retry later")
	case codes.Unauthenticated:
		return gqlerror.Errorf("authentication required")
	default:
		return gqlerror.Errorf("authentication error")
	}
}

func authErrorCodeString(c sessionpb.AuthErrorCode) string {
	switch c {
	case sessionpb.AuthErrorCode_AUTH_ERROR_CODE_AUTHENTICATION_FAILED:
		return "AUTHENTICATION_FAILED"
	case sessionpb.AuthErrorCode_AUTH_ERROR_CODE_RATE_LIMITED:
		return "RATE_LIMITED"
	case sessionpb.AuthErrorCode_AUTH_ERROR_CODE_INVALID_SESSION_STATE:
		return "INVALID_SESSION_STATE"
	case sessionpb.AuthErrorCode_AUTH_ERROR_CODE_INVALID_INPUT:
		return "INVALID_INPUT"
	case sessionpb.AuthErrorCode_AUTH_ERROR_CODE_IDENTITY_ALREADY_LINKED:
		return "IDENTITY_ALREADY_LINKED"
	case sessionpb.AuthErrorCode_AUTH_ERROR_CODE_LINK_UNAUTHORIZED:
		return "LINK_UNAUTHORIZED"
	case sessionpb.AuthErrorCode_AUTH_ERROR_CODE_OIDC_MANUAL_LINK_REQUIRED:
		return "OIDC_MANUAL_LINK_REQUIRED"
	default:
		return ""
	}
}

// mapBackendError converts an authz/profile gRPC error into a client-safe
// GraphQL error without leaking internals.
func mapBackendError(err error) error {
	st, ok := status.FromError(err)
	if !ok {
		return gqlerror.Errorf("request failed")
	}
	switch st.Code() {
	case codes.PermissionDenied:
		return gqlerror.Errorf("forbidden")
	case codes.Unauthenticated:
		return gqlerror.Errorf("authentication required")
	case codes.NotFound:
		return gqlerror.Errorf("not found")
	case codes.AlreadyExists:
		return gqlerror.Errorf("already exists")
	case codes.InvalidArgument:
		return gqlerror.Errorf("invalid request")
	case codes.ResourceExhausted:
		return gqlerror.Errorf("too many requests, please retry later")
	case codes.FailedPrecondition:
		return gqlerror.Errorf("request not allowed in the current state")
	default:
		return gqlerror.Errorf("request failed")
	}
}

// ---- data-plane mappers (authz/profile) ----

func profileModel(p *profilepb.GetProfileResponse) *model.Profile {
	if p == nil {
		return nil
	}
	out := &model.Profile{
		ID:          p.GetId(),
		Username:    p.GetUsername(),
		DisplayName: p.GetDisplayName(),
	}
	out.AvatarURL = strPtr(p.GetAvatarUrl())
	out.Bio = strPtr(p.GetBio())
	out.Locale = strPtr(p.GetLocale())
	out.Timezone = strPtr(p.GetTimezone())
	return out
}

func orgProfileModel(v *profilepb.OrganizationProfileView) *model.OrganizationProfile {
	if v == nil {
		return nil
	}
	out := &model.OrganizationProfile{
		OrganizationID: v.GetOrganizationId(),
		Slug:           v.GetSlug(),
		DisplayName:    v.GetDisplayName(),
	}
	out.Description = strPtr(v.GetDescription())
	if ts := v.GetCreatedAt(); ts != nil {
		out.CreatedAt = rfc3339(ts)
	}
	if ts := v.GetUpdatedAt(); ts != nil {
		out.UpdatedAt = rfc3339(ts)
	}
	return out
}

func roleModel(v *authzpb.RoleView) *model.Role {
	if v == nil {
		return nil
	}
	out := &model.Role{
		RoleID:      v.GetRoleId(),
		Name:        v.GetName(),
		IsSystem:    v.GetIsSystem(),
		Permissions: v.GetPermissions(),
	}
	out.Description = strPtr(v.GetDescription())
	if out.Permissions == nil {
		out.Permissions = []string{}
	}
	return out
}

func memberModel(v *authzpb.MemberView) *model.OrganizationMember {
	if v == nil {
		return nil
	}
	out := &model.OrganizationMember{
		UserID: v.GetUserId(),
		Role:   v.GetRole(),
	}
	if ts := v.GetCreatedAt(); ts != nil {
		out.CreatedAt = rfc3339(ts)
	}
	return out
}

func membershipModel(v *authzpb.OrganizationMembershipView) *model.OrganizationMembership {
	if v == nil {
		return nil
	}
	out := &model.OrganizationMembership{
		OrganizationID: v.GetOrganizationId(),
		Name:           v.GetName(),
		Role:           v.GetRole(),
	}
	out.Description = strPtr(v.GetDescription())
	return out
}

// buildProfileUpdate maps the non-null GraphQL input fields onto an update mask
// and IdentityInformation payload (the profile service's partial-update shape).
func buildProfileUpdate(in model.UpdateProfileInput) (*fieldmaskpb.FieldMask, *claimspb.IdentityInformation) {
	mask := &fieldmaskpb.FieldMask{}
	identity := &claimspb.IdentityInformation{}
	if in.Username != nil {
		mask.Paths = append(mask.Paths, "identity.username")
		identity.SetUsername(*in.Username)
	}
	if in.DisplayName != nil {
		mask.Paths = append(mask.Paths, "identity.name")
		identity.SetName(*in.DisplayName)
	}
	if in.Bio != nil {
		mask.Paths = append(mask.Paths, "identity.bio")
		identity.SetBio(*in.Bio)
	}
	if in.Locale != nil {
		mask.Paths = append(mask.Paths, "identity.locale")
		identity.SetLocale(*in.Locale)
	}
	if in.Timezone != nil {
		mask.Paths = append(mask.Paths, "identity.timezone")
		identity.SetTimezone(*in.Timezone)
	}
	return mask, identity
}

// getProfile fetches a profile by id (public read), used by field resolvers and
// the per-request loader.
func (r *Resolver) getProfile(ctx context.Context, id string) (*model.Profile, error) {
	req := &profilepb.GetProfileRequest{}
	req.SetId(id)
	resp, err := r.Profile.GetProfile(reqctx.OutgoingMetadata(ctx), req)
	if err != nil {
		return nil, mapBackendError(err)
	}
	return profileModel(resp), nil
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// NewProfileLoader builds a per-request profile loader bound to this resolver.
// The service injects one per request so member listings dedupe GetProfile calls.
func (r *Resolver) NewProfileLoader() *loader.ProfileLoader {
	return loader.New(r.getProfile)
}

// profileLoader returns the per-request profile loader, lazily creating one
// bound to this resolver when the middleware did not inject it (e.g. tests).
func (r *Resolver) profileLoader(ctx context.Context) *loader.ProfileLoader {
	if l, ok := loader.FromContext(ctx); ok {
		return l
	}
	return r.NewProfileLoader()
}
