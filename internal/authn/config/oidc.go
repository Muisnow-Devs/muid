package config

import (
	"encoding/json"
	"errors"
	"strings"

	"sanzi.io/muid/internal/authn/identity"
	"sanzi.io/muid/pkg/utils"
)

var ErrOIDCClientConfigRequired = errors.New(
	"authn config: OIDC client config requires provider, endpoint, client_id, client_secret, and redirect_url",
)

type oidcClientJSON struct {
	Provider     string              `json:"provider"`
	Key          string              `json:"key"`
	Name         string              `json:"name"`
	Endpoint     string              `json:"endpoint"`
	ClientID     string              `json:"client_id"`
	ClientSecret string              `json:"client_secret"`
	RedirectURL  string              `json:"redirect_url"`
	Scopes       []string            `json:"scopes"`
	ClaimFields  oidcClaimFieldsJSON `json:"claim_fields"`
}

type oidcClaimFieldsJSON struct {
	Subject       string `json:"subject"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
	Email         string `json:"email"`
	EmailVerified string `json:"email_verified"`
}

type OIDCClients []identity.OIDCProviderConfig

func (clients *OIDCClients) Decode(raw string) error {
	parsed, err := parseOIDCClientsJSON(raw)
	if err != nil {
		return err
	}
	*clients = parsed
	return nil
}

func parseOIDCClientsJSON(raw string) (OIDCClients, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}

	var clients []oidcClientJSON
	err := json.Unmarshal([]byte(raw), &clients)
	if err != nil {
		return nil, err
	}

	out := make(OIDCClients, 0, len(clients))
	for _, client := range clients {
		cfg, err := client.toOIDCProviderConfig()
		if err != nil {
			return nil, err
		}
		out = append(out, cfg)
	}
	return out, nil
}

func (c oidcClientJSON) toOIDCProviderConfig() (identity.OIDCProviderConfig, error) {
	cfg := identity.OIDCProviderConfig{
		Name:         utils.FirstNonEmpty(c.Provider, c.Key, c.Name),
		Endpoint:     strings.TrimSpace(c.Endpoint),
		ClientID:     strings.TrimSpace(c.ClientID),
		ClientSecret: strings.TrimSpace(c.ClientSecret),
		RedirectURL:  strings.TrimSpace(c.RedirectURL),
		Scopes:       utils.TrimNonEmpty(c.Scopes),
		ClaimFields: identity.OIDCClaimFields{
			Subject:       strings.TrimSpace(c.ClaimFields.Subject),
			Name:          strings.TrimSpace(c.ClaimFields.Name),
			Picture:       strings.TrimSpace(c.ClaimFields.Picture),
			Email:         strings.TrimSpace(c.ClaimFields.Email),
			EmailVerified: strings.TrimSpace(c.ClaimFields.EmailVerified),
		},
	}
	if cfg.Name == "" ||
		cfg.Endpoint == "" ||
		cfg.ClientID == "" ||
		cfg.ClientSecret == "" ||
		cfg.RedirectURL == "" {
		return identity.OIDCProviderConfig{}, ErrOIDCClientConfigRequired
	}
	return cfg, nil
}
