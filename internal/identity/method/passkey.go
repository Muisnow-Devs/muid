package method

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	identitystore "sanzi.io/muid/internal/identity/store"
	"sanzi.io/muid/internal/session"
	"sanzi.io/muid/pkg/shared/authn"
)

const (
	CeremonyRegistration   = "registration"
	CeremonyAuthentication = "authentication"
)

// PasskeyChallengePayload contains the WebAuthn options for the next step.
type PasskeyChallengePayload struct {
	Ceremony                               string
	PublicKeyCredentialRequestOptionsJSON  string
	PublicKeyCredentialCreationOptionsJSON string
	TimeoutMillis                          int64
}

// PasskeyAssertionPayload submits a login ceremony assertion response.
type PasskeyAssertionPayload struct {
	CredentialID                    []byte
	ClientDataJSON                  []byte
	CredentialAssertionResponseJSON string
}

func (PasskeyAssertionPayload) PayloadKind() string { return "passkey_assertion" }

// PasskeyCreationPayload submits the registration ceremony response.
type PasskeyCreationPayload struct {
	CredentialCreationResponseJSON string
}

func (PasskeyCreationPayload) PayloadKind() string { return "passkey_creation" }

// PasskeyMethod handles WebAuthn passkey authentication and registration.
// It has no direct database dependency; identity persistence and ceremony-user
// loading are delegated to the injected PasskeyIdentityStore.
type PasskeyMethod struct {
	identityStore   identitystore.PasskeyIdentityStore
	transitionStore session.AuthTransitionStore
	webAuthn        *webauthn.WebAuthn
}

func NewPasskeyMethod(
	identityStore identitystore.PasskeyIdentityStore,
	transitionStore session.AuthTransitionStore,
	wa *webauthn.WebAuthn,
) IdentityMethod {
	return &PasskeyMethod{
		identityStore:   identityStore,
		transitionStore: transitionStore,
		webAuthn:        wa,
	}
}

func (m *PasskeyMethod) Name() string { return "passkey" }

func (m *PasskeyMethod) Start(
	ctx context.Context,
	sessionStore session.SessionStore,
	req StartRequest,
) (Step, error) {
	var challenge *PasskeyChallengePayload

	switch sessionStore.Intent {
	case session.AuthIntentLogin, session.AuthIntentReauth:
		assertion, webAuthnSession, err := m.webAuthn.BeginDiscoverableLogin()
		if err != nil {
			return nil, err
		}

		sessionStore.Flow = &session.PasskeyFlow{
			Ceremony: CeremonyAuthentication,
			Session:  *webAuthnSession,
		}

		optsJSON, err := json.Marshal(assertion.Response)
		if err != nil {
			return nil, err
		}

		challenge = &PasskeyChallengePayload{
			Ceremony:                              CeremonyAuthentication,
			PublicKeyCredentialRequestOptionsJSON: string(optsJSON),
			TimeoutMillis:                         int64(assertion.Response.Timeout),
		}

	case session.AuthIntentLinkAccount:
		if sessionStore.OperationUserID == nil {
			return &FailureStep{
				Code:    authn.ErrCodeInvalidSessionState,
				Message: "session required for passkey registration",
			}, nil
		}
		operationUserID := *sessionStore.OperationUserID

		user, err := m.identityStore.LoadCeremonyUser(ctx, *sessionStore.OperationUserID)
		if err != nil {
			return nil, err
		}

		creation, webAuthnSession, err := m.webAuthn.BeginRegistration(
			user,
			webauthn.WithExclusions(webauthn.Credentials(user.Credentials).CredentialDescriptors()),
			webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementPreferred),
		)
		if err != nil {
			return nil, err
		}

		sessionStore.Flow = &session.PasskeyFlow{
			Ceremony:      CeremonyRegistration,
			Session:       *webAuthnSession,
			SubjectUserID: operationUserID.String(),
		}

		optsJSON, err := json.Marshal(creation.Response)
		if err != nil {
			return nil, err
		}

		challenge = &PasskeyChallengePayload{
			Ceremony:                               CeremonyRegistration,
			PublicKeyCredentialCreationOptionsJSON: string(optsJSON),
			TimeoutMillis:                          int64(creation.Response.Timeout),
		}

	default:
		return &FailureStep{
			Code:    authn.ErrCodeInvalidInput,
			Message: "invalid auth intent for passkey method",
		}, nil
	}

	sess, err := m.transitionStore.Create(ctx, m.Name(), sessionStore)
	if err != nil {
		return nil, err
	}

	return ChallengeStep{
		TransitionID: sess.ID,
		Challenge:    challenge,
	}, nil
}

func (m *PasskeyMethod) Continue(
	ctx context.Context,
	req ContinueRequest,
) (Step, error) {
	sess, err := m.transitionStore.Get(ctx, req.TransitionID)
	if err != nil {
		if errors.Is(err, session.ErrSessionNotFound) {
			return &FailureStep{Err: session.ErrSessionNotFound}, nil
		}
		if errors.Is(err, session.ErrSessionExpired) {
			return &FailureStep{Err: session.ErrSessionExpired}, nil
		}
		return nil, err
	}

	pkFlow, ok := sess.Store.Flow.(*session.PasskeyFlow)
	if !ok {
		return &FailureStep{
			Code:    authn.ErrCodeInvalidSessionState,
			Message: "invalid passkey flow state",
		}, nil
	}

	switch sess.Store.Intent {
	case session.AuthIntentLogin, session.AuthIntentReauth:
		return m.continueLogin(ctx, req, pkFlow)
	case session.AuthIntentLinkAccount:
		return m.continueRegister(ctx, req, pkFlow)
	default:
		return &FailureStep{
			Code:    authn.ErrCodeInvalidSessionState,
			Message: "invalid auth intent for passkey method",
		}, nil
	}
}

func (m *PasskeyMethod) continueLogin(
	ctx context.Context,
	req ContinueRequest,
	pkFlow *session.PasskeyFlow,
) (Step, error) {
	payload, ok := req.Payload.(PasskeyAssertionPayload)
	if !ok {
		return &FailureStep{
			Code:    authn.ErrCodeInvalidInput,
			Message: "expected PasskeyAssertionPayload",
		}, nil
	}

	rawJSON := payload.CredentialAssertionResponseJSON
	if rawJSON == "" {
		rawJSON = string(payload.ClientDataJSON)
	}

	parsed, err := protocol.ParseCredentialRequestResponseBytes([]byte(rawJSON))
	if err != nil {
		return &FailureStep{Code: authn.ErrCodeInvalidInput, Message: err.Error()}, nil
	}

	// The discoverable user handler calls back into the store — no DB in method.
	_, verifiedCredential, err := m.webAuthn.ValidatePasskeyLogin(
		m.discoverableUserHandler(ctx),
		pkFlow.Session,
		parsed,
	)
	if err != nil {
		return &FailureStep{Code: authn.ErrCodeAuthenticationFailed, Message: err.Error()}, nil
	}

	subject := base64.RawURLEncoding.EncodeToString(verifiedCredential.ID)
	return &VerifiedStep{
		Provider: m.Name(),
		Subject:  subject,
	}, nil
}

func (m *PasskeyMethod) continueRegister(
	ctx context.Context,
	req ContinueRequest,
	pkFlow *session.PasskeyFlow,
) (Step, error) {
	payload, ok := req.Payload.(PasskeyCreationPayload)
	if !ok {
		return &FailureStep{
			Code:    authn.ErrCodeInvalidInput,
			Message: "expected PasskeyCreationPayload",
		}, nil
	}

	parsed, err := protocol.ParseCredentialCreationResponseBytes(
		[]byte(payload.CredentialCreationResponseJSON),
	)
	if err != nil {
		return &FailureStep{Code: authn.ErrCodeInvalidInput, Message: err.Error()}, nil
	}

	uid, err := uuid.Parse(pkFlow.SubjectUserID)
	if err != nil {
		return &FailureStep{Code: authn.ErrCodeInvalidSessionState, Message: err.Error()}, nil
	}

	// Load ceremony user from store (no direct DB access in this method).
	user, err := m.identityStore.LoadCeremonyUser(ctx, uid)
	if err != nil {
		return nil, err
	}

	credential, err := m.webAuthn.CreateCredential(user, pkFlow.Session, parsed)
	if err != nil {
		return &FailureStep{Code: authn.ErrCodeAuthenticationFailed, Message: err.Error()}, nil
	}

	deviceType := identitystore.DeviceTypeMultiDevice
	if !credential.Flags.BackupEligible {
		deviceType = identitystore.DeviceTypeSingleDevice
	}

	transports := make([]string, 0, len(credential.Transport))
	for _, tr := range credential.Transport {
		if tr != "" {
			transports = append(transports, string(tr))
		}
	}

	subject := base64.RawURLEncoding.EncodeToString(credential.ID)
	return &VerifiedStep{
		Provider: m.Name(),
		Subject:  subject,
		Identity: VerifiedIdentity{
			IdentityClaims: identitystore.PasskeyIdentityClaims{
				CredentialID:   credential.ID,
				PublicKey:      credential.PublicKey,
				RPID:           pkFlow.Session.RelyingPartyID,
				DeviceType:     deviceType,
				BackupEligible: credential.Flags.BackupEligible,
				BackupState:    credential.Flags.BackupState,
				Transports:     transports,
				DisplayName:    "Passkey",
			},
		},
	}, nil
}

// discoverableUserHandler returns a WebAuthn DiscoverableUserHandler that
// delegates credential lookup to the identity store.
func (m *PasskeyMethod) discoverableUserHandler(
	ctx context.Context,
) webauthn.DiscoverableUserHandler {
	return func(rawID, userHandle []byte) (webauthn.User, error) {
		userID, err := uuid.FromBytes(userHandle)
		if err != nil {
			return nil, err
		}

		user, err := m.identityStore.FindCeremonyUserByCredential(ctx, rawID)
		if err != nil {
			return nil, err
		}

		if user.ID != userID {
			return nil, errors.New("discoverable login: user handle mismatch")
		}

		return user, nil
	}
}
