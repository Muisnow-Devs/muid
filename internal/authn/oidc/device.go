package oidc

import (
	"context"
	"errors"
	"strings"
	"time"

	"sanzi.io/muid/internal/authn/ent"
	"sanzi.io/muid/internal/authn/ent/oidcclient"
	"sanzi.io/muid/internal/authn/oidc/policy"
	"sanzi.io/muid/internal/authn/oidc/store"
)

// DeviceAuthorization is a successful RFC 8628 device authorization response.
type DeviceAuthorization struct {
	DeviceCode              string
	UserCode                string
	VerificationURI         string
	VerificationURIComplete string
	ExpiresIn               int64
	Interval                int64
}

// DeviceApprovalInfo backs the user-facing verification page.
type DeviceApprovalInfo struct {
	ClientID           string
	ClientName         string
	VerificationStatus oidcclient.VerificationStatus
	Scopes             []ScopeDetail
}

// StartDeviceAuthorization begins a device flow for the client.
func (p *Provider) StartDeviceAuthorization(
	ctx context.Context,
	clientID, clientSecret string,
	scopes []string,
) (DeviceAuthorization, error) {
	client, err := p.clientByClientID(ctx, clientID)
	if errors.Is(err, ErrClientNotFound) {
		return DeviceAuthorization{}, oauthError(ErrCodeInvalidClient, "unknown client")
	}
	if err != nil {
		return DeviceAuthorization{}, err
	}

	err = AuthenticateClient(ctx, p.db, client, clientSecret)
	if err != nil {
		return DeviceAuthorization{}, clientAuthError(err)
	}
	err = policy.GrantTypeEnabled(client, policy.GrantTypeDeviceCode)
	if err != nil {
		return DeviceAuthorization{}, oauthError(
			ErrCodeUnauthorizedClient,
			"device_code grant is not enabled for this client",
		)
	}
	err = policy.ClientUsable(client)
	if err != nil {
		return DeviceAuthorization{}, oauthError(ErrCodeUnauthorizedClient, "client is disabled")
	}
	err = policy.ScopesAllowed(client.Scopes, scopes)
	if err != nil {
		return DeviceAuthorization{}, oauthError(
			ErrCodeInvalidScope,
			"requested scope is not allowed for this client",
		)
	}

	interval := int64(p.cfg.DevicePollInterval.Seconds())
	deviceCode, userCode, err := p.devices.Create(ctx, store.DeviceRecord{
		ClientRefID:     client.ID,
		ClientID:        client.ClientID,
		Scopes:          scopes,
		IntervalSeconds: interval,
	})
	if err != nil {
		return DeviceAuthorization{}, err
	}

	verificationURI := p.cfg.DeviceVerificationURI
	return DeviceAuthorization{
		DeviceCode:              deviceCode,
		UserCode:                userCode,
		VerificationURI:         verificationURI,
		VerificationURIComplete: verificationURI + "?user_code=" + userCode,
		ExpiresIn:               int64(p.devices.TTL().Seconds()),
		Interval:                interval,
	}, nil
}

// NormalizeUserCode maps user input to the stored user-code form (uppercase,
// separators stripped).
func NormalizeUserCode(raw string) string {
	cleaned := strings.ToUpper(strings.TrimSpace(raw))
	cleaned = strings.ReplaceAll(cleaned, "-", "")
	return strings.ReplaceAll(cleaned, " ", "")
}

// DeviceAuthorizationInfo loads the approval-page info for a user code.
func (p *Provider) DeviceAuthorizationInfo(
	ctx context.Context,
	userCode string,
) (DeviceApprovalInfo, error) {
	_, record, err := p.devices.GetByUserCode(ctx, NormalizeUserCode(userCode))
	if errors.Is(err, store.ErrNotFound) {
		return DeviceApprovalInfo{}, ErrPendingNotFound
	}
	if err != nil {
		return DeviceApprovalInfo{}, err
	}
	if record.Status != store.DeviceStatusPending {
		return DeviceApprovalInfo{}, ErrPendingNotFound
	}

	client, err := p.clientByRefID(ctx, record.ClientRefID)
	if errors.Is(err, ErrClientNotFound) {
		return DeviceApprovalInfo{}, ErrPendingNotFound
	}
	if err != nil {
		return DeviceApprovalInfo{}, err
	}

	return DeviceApprovalInfo{
		ClientID:           client.ClientID,
		ClientName:         client.ClientName,
		VerificationStatus: client.VerificationStatus,
		Scopes:             p.scopeDetails(ctx, record.Scopes),
	}, nil
}

// DecideDeviceAuthorization records the user's decision on the verification
// page. A policy rejection of the approving user is returned as an
// access_denied *OAuthError and the device record is marked denied.
func (p *Provider) DecideDeviceAuthorization(
	ctx context.Context,
	user SessionUser,
	userCode string,
	approve bool,
) error {
	deviceCode, record, err := p.devices.GetByUserCode(ctx, NormalizeUserCode(userCode))
	if errors.Is(err, store.ErrNotFound) {
		return ErrPendingNotFound
	}
	if err != nil {
		return err
	}
	if record.Status != store.DeviceStatusPending {
		return ErrPendingNotFound
	}

	if !approve {
		record.Status = store.DeviceStatusDenied
		return p.devices.Update(ctx, deviceCode, record)
	}

	client, err := p.clientByRefID(ctx, record.ClientRefID)
	if errors.Is(err, ErrClientNotFound) {
		return ErrPendingNotFound
	}
	if err != nil {
		return err
	}

	err = p.eval.AuthorizeUser(ctx, client, user.UserID, record.Scopes)
	if err != nil {
		mapped := accessPolicyError(err)
		if _, ok := AsOAuthError(mapped); !ok {
			return err
		}
		record.Status = store.DeviceStatusDenied
		updateErr := p.devices.Update(ctx, deviceCode, record)
		if updateErr != nil {
			return updateErr
		}
		return mapped
	}

	err = p.upsertGrant(ctx, user.UserID, client.ID, record.Scopes)
	if err != nil {
		return err
	}

	record.Status = store.DeviceStatusApproved
	record.UserID = user.UserID
	return p.devices.Update(ctx, deviceCode, record)
}

// redeemDeviceCode is the device_code grant on the token endpoint.
func (p *Provider) redeemDeviceCode(
	ctx context.Context,
	client *ent.OIDCClient,
	deviceCode string,
) (TokenOutput, error) {
	err := policy.GrantTypeEnabled(client, policy.GrantTypeDeviceCode)
	if err != nil {
		return TokenOutput{}, oauthError(
			ErrCodeUnauthorizedClient,
			"device_code grant is not enabled for this client",
		)
	}

	allowed, err := p.devices.AllowPoll(ctx, deviceCode, p.cfg.DevicePollInterval)
	if err != nil {
		return TokenOutput{}, err
	}
	if !allowed {
		return TokenOutput{}, oauthError(ErrCodeSlowDown, "")
	}

	record, claimed, err := p.devices.ConsumeApproved(ctx, deviceCode)
	if errors.Is(err, store.ErrNotFound) {
		return TokenOutput{}, oauthError(ErrCodeExpiredToken, "device code expired or unknown")
	}
	if err != nil {
		return TokenOutput{}, err
	}
	if !claimed {
		switch record.Status {
		case store.DeviceStatusDenied:
			deleteErr := p.devices.Delete(ctx, deviceCode, record.UserCode)
			if deleteErr != nil {
				return TokenOutput{}, deleteErr
			}
			return TokenOutput{}, oauthError(ErrCodeAccessDenied, "user denied the request")
		default:
			return TokenOutput{}, oauthError(ErrCodeAuthorizationPending, "")
		}
	}

	if record.ClientID != client.ClientID {
		return TokenOutput{}, oauthError(
			ErrCodeInvalidGrant,
			"device code was issued to another client",
		)
	}

	// Re-check access at redemption: approval may be minutes old.
	err = p.eval.AuthorizeUser(ctx, client, record.UserID, record.Scopes)
	if err != nil {
		mapped := accessPolicyError(err)
		if _, ok := AsOAuthError(mapped); ok {
			return TokenOutput{}, oauthError(ErrCodeAccessDenied, "access revoked")
		}
		return TokenOutput{}, err
	}

	return p.mintTokens(ctx, client, record.UserID, record.Scopes, "", time.Now())
}
