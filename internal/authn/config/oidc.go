package config

import (
	"encoding/json"
	"errors"
	"strings"

	"sanzi.io/muid/pkg/utils"
)

// ErrOIDCClientConfigRequired reports that an OIDC client entry is incomplete.
var ErrOIDCClientConfigRequired = errors.New(
	"authn config: OIDC client config requires provider, endpoint, client_id, client_secret, and redirect_url",
)

// OIDCClaimFields names optional claims extracted from the provider profile.
type OIDCClaimFields struct {
	Subject       string
	Name          string
	Picture       string
	Email         string
	EmailVerified string
}

// OIDCProviderConfig describes a single configured OIDC provider.
type OIDCProviderConfig struct {
	Name         string
	Endpoint     string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	ClaimFields  OIDCClaimFields
}

type oidcClientJSON struct {
	Provider     string              `json:"provider"`
	Key          string              `json:"key"`
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

// OIDCClients is the decoded OIDC provider configuration list.
type OIDCClients []OIDCProviderConfig

// Decode parses raw envconfig input into OIDC provider configurations.
func (clients *OIDCClients) Decode(raw string) error {
	parsed, err := parseOIDCClientsJSON(raw)
	if err != nil {
		return err
	}
	*clients = parsed
	return nil
}

// parseOIDCClientsJSON parses a JSON array of provider definitions.
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

// toOIDCProviderConfig normalizes a single provider definition.
func (c oidcClientJSON) toOIDCProviderConfig() (OIDCProviderConfig, error) {
	name := strings.TrimSpace(c.Provider)
	if name == "" {
		name = strings.TrimSpace(c.Key)
	}

	cfg := OIDCProviderConfig{
		Name:         name,
		Endpoint:     strings.TrimSpace(c.Endpoint),
		ClientID:     strings.TrimSpace(c.ClientID),
		ClientSecret: strings.TrimSpace(c.ClientSecret),
		RedirectURL:  strings.TrimSpace(c.RedirectURL),
		Scopes:       utils.TrimNonEmpty(c.Scopes),
		ClaimFields: OIDCClaimFields{
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
		return OIDCProviderConfig{}, ErrOIDCClientConfigRequired
	}
	return cfg, nil
}
