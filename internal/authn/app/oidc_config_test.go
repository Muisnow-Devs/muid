package app

import (
	"errors"
	"testing"
)

func TestOIDCProviderConfigsFromEnv(t *testing.T) {
	t.Parallel()

	cfg := Config{
		OIDCClientsJSON: `[
			{
				"provider": " google ",
				"endpoint": "https://accounts.google.com",
				"client_id": "google-client",
				"client_secret": "google-secret",
				"redirect_url": "https://app.example.test/auth/callback/google",
				"scopes": [" openid ", "", "profile", "email "],
				"claim_fields": {"picture": "picture"}
			},
			{
				"key": "github",
				"endpoint": "https://github.example.test",
				"client_id": "github-client",
				"client_secret": "github-secret",
				"redirect_url": "https://app.example.test/auth/callback/github",
				"claim_fields": {"picture": "avatar_url"}
			}
		]`,
	}

	got, err := oidcProviderConfigsFromEnv(cfg)
	if err != nil {
		t.Fatalf("oidcProviderConfigsFromEnv() error = %v", err)
	}

	if len(got) != 2 {
		t.Fatalf("len(got) = %d, want 2", len(got))
	}
	if got[0].Name != "google" || got[0].Endpoint != "https://accounts.google.com" {
		t.Fatalf("got[0] = %+v", got[0])
	}
	if got[0].ClaimFields.Picture != "picture" {
		t.Fatalf("got[0].ClaimFields.Picture = %q, want picture", got[0].ClaimFields.Picture)
	}
	if len(got[0].Scopes) != 3 || got[0].Scopes[0] != "openid" || got[0].Scopes[2] != "email" {
		t.Fatalf("got[0].Scopes = %+v, want trimmed non-empty scopes", got[0].Scopes)
	}
	if got[1].Name != "github" {
		t.Fatalf("got[1].Name = %q, want github", got[1].Name)
	}
	if got[1].ClaimFields.Picture != "avatar_url" {
		t.Fatalf("got[1].ClaimFields.Picture = %q, want avatar_url", got[1].ClaimFields.Picture)
	}
}

func TestOIDCProviderConfigsFromEnvEmpty(t *testing.T) {
	t.Parallel()

	got, err := oidcProviderConfigsFromEnv(Config{})
	if err != nil {
		t.Fatalf("oidcProviderConfigsFromEnv() error = %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("len(got) = %d, want 0", len(got))
	}
}

func TestOIDCProviderConfigsFromEnvRequiresFields(t *testing.T) {
	t.Parallel()

	_, err := oidcProviderConfigsFromEnv(Config{
		OIDCClientsJSON: `[{"provider":"google","endpoint":"https://accounts.google.com"}]`,
	})
	if !errors.Is(err, errOIDCClientConfigRequired) {
		t.Fatalf("error = %v, want %v", err, errOIDCClientConfigRequired)
	}
}
