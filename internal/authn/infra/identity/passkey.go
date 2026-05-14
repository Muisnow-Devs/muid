package identity

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	idn "sanzi.io/muid/internal/identity"
	"sanzi.io/muid/internal/authn/ent"
	"sanzi.io/muid/internal/authn/ent/userpasskey"
	"sanzi.io/muid/internal/authn/infra/account"
	"sanzi.io/muid/internal/session"
)

type PasskeyProvider struct {
	transitionStore session.AuthTransitionStore
	accounts        *account.Services
}

func NewPasskeyIdentityProvider(
	transitionStore session.AuthTransitionStore,
	accounts *account.Services,
) idn.IdentityProvider {
	return &PasskeyProvider{
		transitionStore: transitionStore,
		accounts:        accounts,
	}
}

func (p *PasskeyProvider) Name() string {
	return "passkey"
}

func (p *PasskeyProvider) Start(
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

	store := session.SessionStore{
		Flow: session.FlowKindPasskey,
		Step: AuthStepStart,
		Passkey: &session.PasskeyFlow{
			ChallengeB64: challengeB64,
			RPID:         rpID,
		},
	}

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

	return idn.StepResult{
		TransitionId: sess.Id,
		Type:         idn.StepChallenge,
		PasskeyPublicKeyCredentialRequestOptionsJSON: string(optsJSON),
		PasskeyTimeoutMillis:                         60000,
	}, nil
}

func (p *PasskeyProvider) Continue(
	ctx context.Context,
	input idn.ContinueInput,
) (idn.StepResult, error) {
	rawJSON, ok := input.Payload["credential_assertion_response_json"].(string)
	if !ok || rawJSON == "" {
		return idn.StepResult{}, errors.Join(
			idn.ErrInvalidInput,
			errors.New("missing credential_assertion_response_json"),
		)
	}

	sess, err := p.transitionStore.Get(ctx, input.TransitionId)
	if err != nil {
		return idn.StepResult{}, errors.Join(
			idn.ErrSessionNotFound,
			err,
		)
	}

	if sess.Store.Flow != session.FlowKindPasskey || sess.Store.Passkey == nil {
		return idn.StepResult{}, errors.Join(
			idn.ErrInvalidSessionState,
			errors.New("expected passkey transition"),
		)
	}

	if err := verifyPasskeyChallengeBinding(rawJSON, sess.Store.Passkey.ChallengeB64); err != nil {
		return idn.StepResult{}, errors.Join(idn.ErrAuthenticationFailed, err)
	}

	credID, err := extractCredentialID(rawJSON)
	if err != nil {
		return idn.StepResult{}, errors.Join(idn.ErrInvalidInput, err)
	}

	pk, err := p.accounts.DB.UserPasskey.Query().
		Where(userpasskey.CredentialIDEQ(credID)).
		Only(ctx)
	if ent.IsNotFound(err) {
		return idn.StepResult{}, idn.ErrPasskeyNotLinked
	}
	if err != nil {
		return idn.StepResult{}, err
	}

	authResult, err := p.accounts.IssueAuthenticatedSession(ctx, pk.UserID)
	if err != nil {
		return idn.StepResult{}, err
	}

	_ = p.transitionStore.Delete(ctx, sess.Id)

	return idn.StepResult{
		Type:                 idn.StepComplete,
		AuthenticatedResult: authResult,
	}, nil
}

func verifyPasskeyChallengeBinding(assertionJSON, expectedChallengeB64 string) error {
	var outer struct {
		Response struct {
			ClientDataJSON string `json:"clientDataJSON"`
		} `json:"response"`
	}
	if err := json.Unmarshal([]byte(assertionJSON), &outer); err != nil {
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
	if err := json.Unmarshal(raw, &cd); err != nil {
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
	if err := json.Unmarshal([]byte(assertionJSON), &outer); err != nil {
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
