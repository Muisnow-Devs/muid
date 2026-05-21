package identity

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"sanzi.io/muid/internal/authn/account"
	"sanzi.io/muid/internal/authn/ent"
	"sanzi.io/muid/internal/authn/ent/userpasskey"
	idn "sanzi.io/muid/internal/identity"
	"sanzi.io/muid/internal/session"
	"sanzi.io/muid/pkg/shared/pubsub"
)

const (
	passkeyModeLogin    = "login"
	passkeyModeRegister = "register"
)

type PasskeyProvider struct {
	transitionStore session.AuthTransitionStore
	accounts        *account.Accounts
	pubSub          pubsub.PubSub
}

// pubSub is optional; pass nil when mail notifications are not required in tests.
func NewPasskeyIdentityProvider(
	transitionStore session.AuthTransitionStore,
	accounts *account.Accounts,
	pubSub pubsub.PubSub,
) idn.IdentityProvider {
	return &PasskeyProvider{
		transitionStore: transitionStore,
		accounts:        accounts,
		pubSub:          pubSub,
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
	rpID := input.Identifier
	if rpID == "" {
		rpID = "localhost"
	}

	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return idn.StepResult{}, err
	}
	challengeB64 := base64.RawURLEncoding.EncodeToString(challenge)

	store := session.PasskeyStore(session.StepStart, &session.PasskeyFlow{
		ChallengeB64: challengeB64,
		RPID:         rpID,
		Mode:         passkeyModeLogin,
	})

	sess, err := p.transitionStore.Create(ctx, p.Name(), store)
	if err != nil {
		return idn.StepResult{}, err
	}

	opts := map[string]any{
		"challenge":        challengeB64,
		"timeout":          60000,
		"rpId":             rpID,
		"allowCredentials": []any{},
		"userVerification": "preferred",
	}
	optsJSON, err := json.Marshal(opts)
	if err != nil {
		return idn.StepResult{}, err
	}

	return passkeyChallengeStep(sess.Id, string(optsJSON), 60000), nil
}

func (p *PasskeyProvider) startRegister(
	ctx context.Context,
	input idn.StartInput,
) (idn.StepResult, error) {
	linkRes, err := resolveLinkSession(
		ctx,
		p.accounts,
		idn.IntentLinkAccount,
		input.LinkSessionToken,
	)
	if err != nil {
		return idn.StepResult{}, err
	}

	rpID := input.Identifier
	if rpID == "" {
		rpID = "localhost"
	}

	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return idn.StepResult{}, err
	}
	challengeB64 := base64.RawURLEncoding.EncodeToString(challenge)

	store := session.PasskeyStore(session.StepStart, &session.PasskeyFlow{
		ChallengeB64:  challengeB64,
		RPID:          rpID,
		Mode:          passkeyModeRegister,
		SubjectUserID: linkRes.UserID.String(),
	})

	sess, err := p.transitionStore.Create(ctx, p.Name(), store)
	if err != nil {
		return idn.StepResult{}, err
	}

	exclude, err := p.excludeCredentials(ctx, linkRes.UserID)
	if err != nil {
		return idn.StepResult{}, err
	}

	ref, err := p.accounts.Store.DB.UserRef.Get(ctx, linkRes.UserID)
	if err != nil {
		return idn.StepResult{}, err
	}

	opts := map[string]any{
		"challenge": challengeB64,
		"timeout":   60000,
		"rp": map[string]any{
			"id":   rpID,
			"name": "muid",
		},
		"user": map[string]any{
			"id":          base64.RawURLEncoding.EncodeToString(linkRes.UserID[:]),
			"name":        ref.Email,
			"displayName": ref.Email,
		},
		"pubKeyCredParams": []map[string]any{
			{"type": "public-key", "alg": -7},
			{"type": "public-key", "alg": -257},
		},
		"excludeCredentials": exclude,
		"authenticatorSelection": map[string]any{
			"userVerification": "preferred",
		},
		"attestation": "none",
	}
	optsJSON, err := json.Marshal(opts)
	if err != nil {
		return idn.StepResult{}, err
	}

	return passkeyChallengeStep(sess.Id, string(optsJSON), 60000), nil
}

func passkeyChallengeStep(transitionID, optsJSON string, timeoutMillis int64) idn.StepResult {
	return idn.StepResult{
		TransitionId: transitionID,
		Type:         idn.StepChallenge,
		Payload: &idn.StepPayload{
			Passkey: &idn.PasskeyChallengePayload{
				PublicKeyCredentialRequestOptionsJSON: optsJSON,
				TimeoutMillis:                         timeoutMillis,
			},
		},
	}
}

func (p *PasskeyProvider) excludeCredentials(
	ctx context.Context,
	userID uuid.UUID,
) ([]map[string]any, error) {
	rows, err := p.accounts.Store.DB.UserPasskey.Query().
		Where(userpasskey.UserIDEQ(userID), userpasskey.RevokedEQ(false)).
		All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, map[string]any{
			"type": "public-key",
			"id":   base64.RawURLEncoding.EncodeToString(row.CredentialID),
		})
	}
	return out, nil
}

func (p *PasskeyProvider) Continue(
	ctx context.Context,
	input idn.ContinueInput,
) (idn.StepResult, error) {
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

	if pkFlow.Mode == passkeyModeRegister {
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

	err := verifyPasskeyChallengeBinding(rawJSON, pkFlow.ChallengeB64)
	if err != nil {
		return idn.StepResult{}, errors.Join(idn.ErrAuthenticationFailed, err)
	}

	credID, err := extractCredentialID(rawJSON)
	if err != nil {
		return idn.StepResult{}, errors.Join(idn.ErrInvalidInput, err)
	}

	pk, err := p.accounts.Store.DB.UserPasskey.Query().
		Where(userpasskey.CredentialIDEQ(credID)).
		Only(ctx)
	if ent.IsNotFound(err) {
		return idn.StepResult{}, idn.ErrPasskeyNotLinked
	}
	if err != nil {
		return idn.StepResult{}, err
	}

	p.transitionStore.Delete(ctx, sess.Id)

	return idn.StepResult{
		Type: idn.StepAuthenticated,
		Authenticated: &idn.AuthenticatedIdentity{
			UserID: pk.UserID.String(),
		},
	}, nil
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

	err := verifyPasskeyCreationChallengeBinding(rawJSON, pkFlow.ChallengeB64)
	if err != nil {
		return idn.StepResult{}, errors.Join(idn.ErrAuthenticationFailed, err)
	}

	credID, err := extractCreationCredentialID(rawJSON)
	if err != nil {
		return idn.StepResult{}, errors.Join(idn.ErrInvalidInput, err)
	}

	attObj, err := extractAttestationObject(rawJSON)
	if err != nil {
		return idn.StepResult{}, errors.Join(idn.ErrInvalidInput, err)
	}

	uid, err := uuid.Parse(pkFlow.SubjectUserID)
	if err != nil {
		return idn.StepResult{}, errors.Join(idn.ErrInvalidSessionState, err)
	}

	err = p.accounts.Passkey.LinkPasskey(
		ctx,
		p.pubSub,
		uid,
		credID,
		attObj,
		pkFlow.RPID,
		string(userpasskey.DeviceTypeMultiDevice),
		"Passkey",
	)
	if err != nil {
		return idn.StepResult{}, err
	}

	p.transitionStore.Delete(ctx, sess.Id)

	wire := strings.TrimSpace(input.LinkSessionToken)
	if wire != "" {
		res, err := p.accounts.Session.ResolveSessionToken(ctx, wire)
		if err != nil {
			return idn.StepResult{}, err
		}
		if res.UserID != uid {
			return idn.StepResult{}, idn.ErrLinkUnauthorized
		}
	}

	return idn.StepResult{Type: idn.StepLinked}, nil
}

func verifyPasskeyChallengeBinding(assertionJSON, expectedChallengeB64 string) error {
	var outer struct {
		Response struct {
			ClientDataJSON string `json:"clientDataJSON"`
		} `json:"response"`
	}
	err := json.Unmarshal([]byte(assertionJSON), &outer)
	if err != nil {
		return fmt.Errorf("assertion json: %w", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(outer.Response.ClientDataJSON)
	if err != nil {
		return fmt.Errorf("clientDataJSON base64: %w", err)
	}
	var cd struct {
		Challenge string `json:"challenge"`
		Type      string `json:"type"`
	}
	err = json.Unmarshal(raw, &cd)
	if err != nil {
		return fmt.Errorf("client data: %w", err)
	}
	if cd.Type != "webauthn.get" {
		return errors.New("unexpected clientData type")
	}
	if cd.Challenge != expectedChallengeB64 {
		return errors.New("webauthn challenge mismatch")
	}
	return nil
}

func extractCredentialID(assertionJSON string) ([]byte, error) {
	var outer struct {
		RawID string `json:"rawId"`
		ID    string `json:"id"`
	}
	err := json.Unmarshal([]byte(assertionJSON), &outer)
	if err != nil {
		return nil, err
	}
	b64 := outer.RawID
	if b64 == "" {
		b64 = outer.ID
	}
	if b64 == "" {
		return nil, errors.New("missing rawId/id")
	}
	raw, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, errors.New("empty credential id")
	}
	return raw, nil
}
