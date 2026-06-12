package core

import (
	"errors"
	"strings"
	"testing"

	idclaims "sanzi.io/muid/api/proto/shared/v1/claims"
	"sanzi.io/muid/internal/profile/updatemask"
)

func identityWith(set func(*idclaims.IdentityInformation)) *idclaims.IdentityInformation {
	idn := &idclaims.IdentityInformation{}
	set(idn)
	return idn
}

func TestProfileFieldsConsistentWithUpdatemask(t *testing.T) {
	t.Parallel()

	for path, spec := range profileFields {
		canon, err := updatemask.CanonicalProfilePath(path)
		if err != nil {
			t.Errorf("registry path %q is not a valid mask path: %v", path, err)
			continue
		}
		if canon != path {
			t.Errorf("registry path %q is not canonical (canonical: %q)", path, canon)
		}

		resp, err := updatemask.CanonicalGetProfileResponsePath(spec.responsePath)
		if err != nil {
			t.Errorf("registry path %q responsePath %q is not a GetProfileResponse field: %v",
				path, spec.responsePath, err)
			continue
		}
		if resp != spec.responsePath {
			t.Errorf("registry path %q responsePath %q is not canonical (canonical: %q)",
				path, spec.responsePath, resp)
		}
	}
}

func TestParseFields(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		path    string
		idn     *idclaims.IdentityInformation
		want    string
		wantErr bool
	}{
		{
			name: "username valid trimmed",
			path: "identity.username",
			idn: identityWith(
				func(i *idclaims.IdentityInformation) { i.SetUsername(" alice.01 ") },
			),
			want: "alice.01",
		},
		{
			name: "username uppercase rejected",
			path: "identity.username",
			idn: identityWith(
				func(i *idclaims.IdentityInformation) { i.SetUsername("Alice.01") },
			),
			wantErr: true,
		},
		{
			name:    "username nil identity",
			path:    "identity.username",
			idn:     nil,
			wantErr: true,
		},
		{
			name:    "username empty",
			path:    "identity.username",
			idn:     identityWith(func(i *idclaims.IdentityInformation) { i.SetUsername("   ") }),
			wantErr: true,
		},
		{
			name: "username invalid leading underscore",
			path: "identity.username",
			idn: identityWith(
				func(i *idclaims.IdentityInformation) { i.SetUsername("_alice") },
			),
			wantErr: true,
		},
		{
			name:    "username too short",
			path:    "identity.username",
			idn:     identityWith(func(i *idclaims.IdentityInformation) { i.SetUsername("ab") }),
			wantErr: true,
		},
		{
			name: "locale trimmed",
			path: "identity.locale",
			idn:  identityWith(func(i *idclaims.IdentityInformation) { i.SetLocale(" zh-TW ") }),
			want: "zh-TW",
		},
		{
			name:    "locale nil identity",
			path:    "identity.locale",
			idn:     nil,
			wantErr: true,
		},
		{
			name:    "locale empty",
			path:    "identity.locale",
			idn:     identityWith(func(i *idclaims.IdentityInformation) { i.SetLocale("") }),
			wantErr: true,
		},
		{
			name: "locale too long",
			path: "identity.locale",
			idn: identityWith(
				func(i *idclaims.IdentityInformation) { i.SetLocale(strings.Repeat("x", 33)) },
			),
			wantErr: true,
		},
		{
			name: "timezone valid",
			path: "identity.timezone",
			idn: identityWith(
				func(i *idclaims.IdentityInformation) { i.SetTimezone("America/New_York") },
			),
			want: "America/New_York",
		},
		{
			name: "timezone empty allowed",
			path: "identity.timezone",
			idn:  identityWith(func(i *idclaims.IdentityInformation) { i.SetTimezone("  ") }),
			want: "",
		},
		{
			name: "timezone not IANA",
			path: "identity.timezone",
			idn: identityWith(
				func(i *idclaims.IdentityInformation) { i.SetTimezone("Not/AZone") },
			),
			wantErr: true,
		},
		{
			name: "timezone too long",
			path: "identity.timezone",
			idn: identityWith(
				func(i *idclaims.IdentityInformation) { i.SetTimezone(strings.Repeat("x", 65)) },
			),
			wantErr: true,
		},
		{
			name:    "timezone nil identity",
			path:    "identity.timezone",
			idn:     nil,
			wantErr: true,
		},
		{
			name: "bio trimmed",
			path: "identity.bio",
			idn:  identityWith(func(i *idclaims.IdentityInformation) { i.SetBio("  hello  ") }),
			want: "hello",
		},
		{
			name: "bio too long",
			path: "identity.bio",
			idn: identityWith(
				func(i *idclaims.IdentityInformation) { i.SetBio(strings.Repeat("x", 1025)) },
			),
			wantErr: true,
		},
		{
			name:    "bio nil identity",
			path:    "identity.bio",
			idn:     nil,
			wantErr: true,
		},
		{
			name: "display name from name",
			path: "identity.name",
			idn: identityWith(
				func(i *idclaims.IdentityInformation) { i.SetName(" Ada Lovelace ") },
			),
			want: "Ada Lovelace",
		},
		{
			name: "display name from given and family",
			path: "identity.given_name",
			idn: identityWith(func(i *idclaims.IdentityInformation) {
				i.SetGivenName("Ada")
				i.SetFamilyName("Lovelace")
			}),
			want: "Ada Lovelace",
		},
		{
			name: "display name from family only",
			path: "identity.family_name",
			idn: identityWith(
				func(i *idclaims.IdentityInformation) { i.SetFamilyName("Lovelace") },
			),
			want: "Lovelace",
		},
		{
			name:    "display name no fields",
			path:    "identity.name",
			idn:     identityWith(func(i *idclaims.IdentityInformation) {}),
			wantErr: true,
		},
		{
			name:    "display name nil identity",
			path:    "identity.name",
			idn:     nil,
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			spec, ok := profileFields[tc.path]
			if !ok {
				t.Fatalf("path %q not in registry", tc.path)
			}

			got, err := spec.parse(tc.idn)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parse(%q) = %q, want error", tc.path, got)
				}
				var ia InvalidArgumentError
				if !errors.As(err, &ia) {
					t.Fatalf("parse(%q) error = %v, want InvalidArgumentError", tc.path, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("parse(%q) error = %v", tc.path, err)
			}
			if got != tc.want {
				t.Fatalf("parse(%q) = %q, want %q", tc.path, got, tc.want)
			}
		})
	}
}

func TestResponsePathsFor(t *testing.T) {
	t.Parallel()

	got := responsePathsFor([]string{
		"identity.name",
		"identity.given_name",
		"identity.username",
		"identity.bio",
	})
	want := []string{"bio", "display_name", "username"}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}
