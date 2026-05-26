package identity

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"sanzi.io/muid/internal/authn/account"
	"sanzi.io/muid/internal/authn/ent/userpasskey"
	idn "sanzi.io/muid/internal/identity"
	"sanzi.io/muid/internal/session"
)

const (
	PasskeyCeremonyAuthentication = "authentication"
	PasskeyCeremonyRegistration   = "registration"
)

type PasskeyConfig struct {
	RPID          string
	RPDisplayName string
	RPOrigins     []string
}

type PasskeyProvider struct {
	transitionStore session.AuthTransitionStore
	passkeys        account.Passkey
	sessions        account.Session
	notifier        account.Notifier
	webAuthn        *webauthn.WebAuthn
}

// notifier is optional; pass nil when mail notifications are not required in tests.
func NewPasskeyIdentityProvider(
	transitionStore session.AuthTransitionStore,
	passkeys account.Passkey,
	sessions account.Session,
	notifier account.Notifier,
) idn.IdentityProvider {
	provider, err := NewPasskeyIdentityProviderWithConfig(
		transitionStore,
		passkeys,
		sessions,
		notifier,
		DefaultPasskeyConfig(),
	)
	if err != nil {
		panic(err)
	}
	return provider
}

func NewPasskeyIdentityProviderWithConfig(
	transitionStore session.AuthTransitionStore,
	passkeys account.Passkey,
	sessions account.Session,
	notifier account.Notifier,
	config PasskeyConfig,
) (idn.IdentityProvider, error) {
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          config.RPID,
		RPDisplayName: config.RPDisplayName,
		RPOrigins:     config.RPOrigins,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			UserVerification: protocol.VerificationPreferred,
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
		},
		AttestationPreference: protocol.PreferNoAttestation,
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Enforce: true, Timeout: time.Minute},
			Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: time.Minute},
		},
	})
	if err != nil {
		return nil, err
	}
	return &PasskeyProvider{
		transitionStore: transitionStore,
		passkeys:        passkeys,
		sessions:        sessions,
		notifier:        notifier,
		webAuthn:        wa,
	}, nil
}

func DefaultPasskeyConfig() PasskeyConfig {
	return PasskeyConfig{
		RPID:          "localhost",
		RPDisplayName: "muid",
		RPOrigins:     []string{"http://localhost", "http://localhost:3000", "https://localhost"},
	}
}

func (p *PasskeyProvider) Name() string {
	return "passkey"
}

func (p *PasskeyProvider) Start(
	ctx context.Context,
	input idn.StartInput,
) (idn.StepResult, error) {
	intent := input.Intent
	if intent == idn.IntentUnspecified {
		intent = idn.IntentLogin
	}
	if intent == idn.IntentLinkAccount {
		return p.startRegister(ctx, input)
	}
	return p.startLogin(ctx, input)
}

func (p *PasskeyProvider) startLogin(
	ctx context.Context,
	input idn.StartInput,
) (idn.StepResult, error) {
	assertion, webAuthnSession, err := p.webAuthn.BeginDiscoverableLogin()
	if err != nil {
		return idn.StepResult{}, err
	}

	store := session.PasskeyStore(session.StepStart, &session.PasskeyFlow{
		Ceremony: PasskeyCeremonyAuthentication,
		Session:  *webAuthnSession,
	})
	session.ApplyClientMeta(&store, input.Client)

	sess, err := p.transitionStore.Create(ctx, p.Name(), store)
	if err != nil {
		return idn.StepResult{}, err
	}

	optsJSON, err := json.Marshal(assertion.Response)
	if err != nil {
		return idn.StepResult{}, err
	}

	return passkeyChallengeStep(
		sess.Id,
		PasskeyCeremonyAuthentication,
		string(optsJSON),
		"",
		int64(assertion.Response.Timeout),
	), nil
}

func (p *PasskeyProvider) startRegister(
	ctx context.Context,
	input idn.StartInput,
) (idn.StepResult, error) {
	linkRes, err := resolveLinkSession(
		ctx,
		p.sessions,
		idn.IntentLinkAccount,
		input.LinkSessionToken,
	)
	if err != nil {
		return idn.StepResult{}, err
	}

	user, err := p.passkeyUserByID(ctx, linkRes.UserID)
	if err != nil {
		return idn.StepResult{}, err
	}

	creation, webAuthnSession, err := p.webAuthn.BeginRegistration(
		user,
		webauthn.WithExclusions(webauthn.Credentials(user.credentials).CredentialDescriptors()),
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementPreferred),
	)
	if err != nil {
		return idn.StepResult{}, err
	}

	store := session.PasskeyStore(session.StepStart, &session.PasskeyFlow{
		Ceremony:      PasskeyCeremonyRegistration,
		Session:       *webAuthnSession,
		SubjectUserID: linkRes.UserID.String(),
	})
	session.ApplyClientMeta(&store, input.Client)
	sess, err := p.transitionStore.Create(ctx, p.Name(), store)
	if err != nil {
		return idn.StepResult{}, err
	}

	optsJSON, err := json.Marshal(creation.Response)
	if err != nil {
		return idn.StepResult{}, err
	}

	return passkeyChallengeStep(
		sess.Id,
		PasskeyCeremonyRegistration,
		"",
		string(optsJSON),
		int64(creation.Response.Timeout),
	), nil
}

func (p *PasskeyProvider) Continue(
	ctx context.Context,
	input idn.ContinueInput,
) (idn.StepResult, error) {
	switch input.ContinueState {
	case idn.ContinueStateChallenge:
		return p.continuePasskeyChallenge(ctx, input)
	default:
		return idn.StepResult{}, idn.ErrInvalidInput
	}
}

func (p *PasskeyProvider) continuePasskeyChallenge(
	ctx context.Context,
	input idn.ContinueInput,
) (idn.StepResult, error) {
	err := idn.ValidateContinueChallenge(input)
	if err != nil {
		return idn.StepResult{}, err
	}

	sess, err := p.transitionStore.Get(ctx, input.TransitionId)
	if err != nil {
		return idn.StepResult{}, errors.Join(
			idn.ErrSessionNotFound,
			err,
		)
	}

	pkFlow, ok := sess.Store.PasskeyFlowState()
	if !ok {
		return idn.StepResult{}, errors.Join(
			idn.ErrInvalidSessionState,
			errors.New("expected passkey transition"),
		)
	}

	if pkFlow.Ceremony == PasskeyCeremonyRegistration {
		return p.continueRegister(ctx, input, sess, pkFlow)
	}
	return p.continueLogin(ctx, input, sess, pkFlow)
}

func (p *PasskeyProvider) continueLogin(
	ctx context.Context,
	input idn.ContinueInput,
	sess session.AuthSession,
	pkFlow *session.PasskeyFlow,
) (idn.StepResult, error) {
	rawJSON, ok := input.Payload["credential_assertion_response_json"].(string)
	if !ok || rawJSON == "" {
		return idn.StepResult{}, errors.Join(
			idn.ErrInvalidInput,
			errors.New("missing credential_assertion_response_json"),
		)
	}

	parsed, err := protocol.ParseCredentialRequestResponseBytes([]byte(rawJSON))
	if err != nil {
		return idn.StepResult{}, errors.Join(idn.ErrInvalidInput, err)
	}

	user, verifiedCredential, err := p.webAuthn.ValidatePasskeyLogin(
		p.discoverableUserHandler(ctx),
		pkFlow.Session,
		parsed,
	)
	if err != nil {
		return idn.StepResult{}, errors.Join(idn.ErrAuthenticationFailed, err)
	}

	passkeyUser, ok := user.(*passkeyUser)
	if !ok {
		return idn.StepResult{}, idn.ErrInvalidSessionState
	}

	err = p.passkeys.UpdatePasskeyUsage(ctx, account.UpdatePasskeyUsageConfig{
		CredentialID: verifiedCredential.ID,
		BackupState:  verifiedCredential.Flags.BackupState,
		SignCount:    verifiedCredential.Authenticator.SignCount,
		LastUsedAt:   time.Now().UTC(),
	})
	if err != nil {
		return idn.StepResult{}, err
	}

	return authenticatedStep(passkeyUser.id.String(), sess.Store), nil
}

func (p *PasskeyProvider) continueRegister(
	ctx context.Context,
	input idn.ContinueInput,
	sess session.AuthSession,
	pkFlow *session.PasskeyFlow,
) (idn.StepResult, error) {
	rawJSON, ok := input.Payload[passkeyCreationPayloadKey].(string)
	if !ok || rawJSON == "" {
		return idn.StepResult{}, errors.Join(
			idn.ErrInvalidInput,
			errors.New("missing credential_creation_response_json"),
		)
	}

	parsed, err := protocol.ParseCredentialCreationResponseBytes([]byte(rawJSON))
	if err != nil {
		return idn.StepResult{}, errors.Join(idn.ErrInvalidInput, err)
	}

	uid, err := uuid.Parse(pkFlow.SubjectUserID)
	if err != nil {
		return idn.StepResult{}, errors.Join(idn.ErrInvalidSessionState, err)
	}

	user, err := p.passkeyUserByID(ctx, uid)
	if err != nil {
		return idn.StepResult{}, err
	}

	credential, err := p.webAuthn.CreateCredential(user, pkFlow.Session, parsed)
	if err != nil {
		return idn.StepResult{}, errors.Join(idn.ErrAuthenticationFailed, err)
	}

	err = p.passkeys.LinkPasskey(ctx, account.LinkPasskeyConfig{
		UserId:         uid,
		CredentialID:   credential.ID,
		PublicKey:      credential.PublicKey,
		RpID:           pkFlow.Session.RelyingPartyID,
		DeviceType:     passkeyDeviceType(credential),
		Name:           "Passkey",
		BackupEligible: credential.Flags.BackupEligible,
		BackupState:    credential.Flags.BackupState,
		SignCount:      credential.Authenticator.SignCount,
		Transports:     credentialTransportStrings(credential.Transport),
		AAGUID:         credential.Authenticator.AAGUID,
	})
	if err != nil {
		return idn.StepResult{}, err
	}

	if p.notifier != nil {
		err = p.notifier.NotifyPasskeyAdded(
			ctx,
			uid,
			"Passkey",
			account.MailDeliveryPrefs{
				Locale:   sess.Store.Locale,
				Timezone: sess.Store.Timezone,
			},
		)
		if err != nil {
			return idn.StepResult{}, err
		}
	}

	linkRes, err := resolveLinkSession(
		ctx,
		p.sessions,
		idn.IntentLinkAccount,
		input.LinkSessionToken,
	)
	if err != nil {
		return idn.StepResult{}, err
	}
	if linkRes.UserID != uid {
		return idn.StepResult{}, idn.ErrLinkUnauthorized
	}

	return idn.StepResult{Type: idn.StepLinked}, nil
}

func passkeyChallengeStep(
	transitionID string,
	ceremony string,
	requestOptionsJSON string,
	creationOptionsJSON string,
	timeoutMillis int64,
) idn.StepResult {
	return idn.StepResult{
		TransitionId: transitionID,
		Type:         idn.StepChallenge,
		Payload: &idn.StepPayload{
			Passkey: &idn.PasskeyChallengePayload{
				Ceremony:                               ceremony,
				PublicKeyCredentialRequestOptionsJSON:  requestOptionsJSON,
				PublicKeyCredentialCreationOptionsJSON: creationOptionsJSON,
				TimeoutMillis:                          timeoutMillis,
			},
		},
	}
}

type passkeyUser struct {
	id          uuid.UUID
	name        string
	displayName string
	credentials []webauthn.Credential
}

func (u *passkeyUser) WebAuthnID() []byte { return u.id[:] }

func (u *passkeyUser) WebAuthnName() string { return u.name }

func (u *passkeyUser) WebAuthnDisplayName() string { return u.displayName }

func (u *passkeyUser) WebAuthnCredentials() []webauthn.Credential {
	return u.credentials
}

func (p *PasskeyProvider) passkeyUserByID(
	ctx context.Context,
	userID uuid.UUID,
) (*passkeyUser, error) {
	ceremonyUser, err := p.passkeys.LoadCeremonyUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	return passkeyUserFromCeremony(ceremonyUser), nil
}

func (p *PasskeyProvider) discoverableUserHandler(
	ctx context.Context,
) webauthn.DiscoverableUserHandler {
	return func(rawID, userHandle []byte) (webauthn.User, error) {
		ceremonyUser, err := p.passkeys.LoadCeremonyUserDiscoverable(ctx, rawID, userHandle)
		if err != nil {
			return nil, err
		}
		return passkeyUserFromCeremony(ceremonyUser), nil
	}
}

func passkeyUserFromCeremony(u *account.PasskeyCeremonyUser) *passkeyUser {
	if u == nil {
		return nil
	}
	return &passkeyUser{
		id:          u.UserID,
		name:        u.Name,
		displayName: u.DisplayName,
		credentials: u.Credentials,
	}
}

func passkeyDeviceType(credential *webauthn.Credential) string {
	if credential.Flags.BackupEligible {
		return string(userpasskey.DeviceTypeMultiDevice)
	}
	return string(userpasskey.DeviceTypeSingleDevice)
}

func credentialTransportStrings(
	transports []protocol.AuthenticatorTransport,
) []string {
	out := make([]string, 0, len(transports))
	for _, transport := range transports {
		if transport != "" {
			out = append(out, string(transport))
		}
	}
	return out
}
