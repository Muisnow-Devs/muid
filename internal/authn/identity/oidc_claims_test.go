package identity

import (
	"encoding/json"
	"testing"
)

func TestOIDCClaimsFromRawDefaults(t *testing.T) {
	t.Parallel()

	raw := rawOIDCClaims(t, `{
		"sub": "sub-1",
		"name": "Ada Lovelace",
		"picture": "https://cdn.example.test/ada.png",
		"email": "ada@example.test",
		"email_verified": true
	}`)

	got := oidcClaimsFromRaw(raw, OIDCClaimFields{})
	if got.Subject != "sub-1" {
		t.Fatalf("Subject = %q, want sub-1", got.Subject)
	}
	if got.Name != "Ada Lovelace" {
		t.Fatalf("Name = %q, want Ada Lovelace", got.Name)
	}
	if got.Picture != "https://cdn.example.test/ada.png" {
		t.Fatalf("Picture = %q, want default picture claim", got.Picture)
	}
	if got.Email != "ada@example.test" || !got.EmailVerified {
		t.Fatalf("email claims = %q/%v, want ada@example.test/true", got.Email, got.EmailVerified)
	}
}

func TestOIDCClaimsFromRawCustomPictureField(t *testing.T) {
	t.Parallel()

	raw := rawOIDCClaims(t, `{
		"sub": "sub-2",
		"name": "Grace Hopper",
		"avatar_url": "https://avatars.example.test/grace.png",
		"email": "grace@example.test",
		"email_verified": "true"
	}`)

	got := oidcClaimsFromRaw(raw, OIDCClaimFields{Picture: "avatar_url"})
	if got.Picture != "https://avatars.example.test/grace.png" {
		t.Fatalf("Picture = %q, want custom avatar_url claim", got.Picture)
	}
	if !got.EmailVerified {
		t.Fatalf("EmailVerified = false, want true")
	}
}

func TestOIDCMergeClaimsFillsMissingValues(t *testing.T) {
	t.Parallel()

	primary := OIDCClaims{Subject: "sub-3", Email: "existing@example.test"}
	secondary := OIDCClaims{
		Subject:       "userinfo-sub",
		Name:          "User Info Name",
		Picture:       "https://avatars.example.test/userinfo.png",
		Email:         "userinfo@example.test",
		EmailVerified: true,
	}

	got := oidcMergeClaims(primary, secondary)
	if got.Subject != "sub-3" {
		t.Fatalf("Subject = %q, want sub-3", got.Subject)
	}
	if got.Email != "existing@example.test" {
		t.Fatalf("Email = %q, want existing@example.test", got.Email)
	}
	if got.Name != "User Info Name" {
		t.Fatalf("Name = %q, want User Info Name", got.Name)
	}
	if got.Picture != "https://avatars.example.test/userinfo.png" {
		t.Fatalf("Picture = %q, want userinfo picture", got.Picture)
	}
	if !got.EmailVerified {
		t.Fatalf("EmailVerified = false, want true")
	}
}

func TestOIDCScopesAddOpenID(t *testing.T) {
	t.Parallel()

	got := oidcScopes([]string{"profile", "email"})
	want := []string{"openid", "profile", "email"}
	if len(got) != len(want) {
		t.Fatalf("len(got) = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func rawOIDCClaims(t *testing.T, input string) map[string]json.RawMessage {
	t.Helper()

	var raw map[string]json.RawMessage
	err := json.Unmarshal([]byte(input), &raw)
	if err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	return raw
}
