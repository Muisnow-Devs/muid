package config

import (
	"errors"
	"testing"
)

func TestOIDCClientsDecode(t *testing.T) {
	t.Parallel()

	var got OIDCClients
	err := got.Decode(`[
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
	]`)
	if err != nil {
		t.Fatalf("OIDCClients.Decode() error = %v", err)
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

func TestOIDCClientsDecodeEmpty(t *testing.T) {
	t.Parallel()

	var got OIDCClients
	err := got.Decode("")
	if err != nil {
		t.Fatalf("OIDCClients.Decode() error = %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("len(got) = %d, want 0", len(got))
	}
}

func TestOIDCClientsDecodeRequiresFields(t *testing.T) {
	t.Parallel()

	var clients OIDCClients
	err := clients.Decode(`[{"provider":"google","endpoint":"https://accounts.google.com"}]`)
	if !errors.Is(err, ErrOIDCClientConfigRequired) {
		t.Fatalf("error = %v, want %v", err, ErrOIDCClientConfigRequired)
	}
}
