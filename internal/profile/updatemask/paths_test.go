package updatemask

import (
	"errors"
	"testing"

	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

func TestCanonicalProfilePath(t *testing.T) {
	t.Parallel()
	cases := []struct {
		raw     string
		want    string
		wantErr error
	}{
		{"identity.name", "identity.name", nil},
		{" identity.givenName ", "identity.given_name", nil},
		{"IDENTITY.USERNAME", "identity.username", nil},
		{"identity.locale", "identity.locale", nil},
		{"identity.bio", "identity.bio", nil},
		{"identity.Bio", "identity.bio", nil},
		{"identity.email", "identity.email", nil},
		{"Identity.EmailVerified", "identity.email_verified", nil},
		{"identity.name.extra", "", ErrUnknownPath},
		{"display_name", "", ErrUnknownPath},
		{"profile.display_name", "", ErrUnknownPath},
		{"identity.nope", "", ErrUnknownPath},
		{"", "", ErrUnknownPath},
		{"   ", "", ErrUnknownPath},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			t.Parallel()
			got, err := CanonicalProfilePath(tc.raw)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err: got %v want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestSortedUniqueCanonicalPaths(t *testing.T) {
	t.Parallel()
	t.Run("dedupes and sorts", func(t *testing.T) {
		t.Parallel()
		mask := &fieldmaskpb.FieldMask{
			Paths: []string{
				"identity.locale",
				"identity.locale",
				"identity.givenName",
				"identity.given_name",
			},
		}
		got, err := SortedUniqueCanonicalPaths(mask)
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"identity.given_name", "identity.locale"}
		if len(got) != len(want) {
			t.Fatalf("got %v want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("got %v want %v", got, want)
			}
		}
	})
	t.Run("empty mask", func(t *testing.T) {
		t.Parallel()
		_, err := SortedUniqueCanonicalPaths(&fieldmaskpb.FieldMask{Paths: nil})
		if !errors.Is(err, ErrEmptyMask) {
			t.Fatalf("got %v", err)
		}
		_, err = SortedUniqueCanonicalPaths(nil)
		if !errors.Is(err, ErrEmptyMask) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestCanonicalGetProfileResponsePath(t *testing.T) {
	t.Parallel()
	cases := []struct {
		raw     string
		want    string
		wantErr error
	}{
		{"display_name", "display_name", nil},
		{"displayName", "display_name", nil},
		{"avatar_url", "avatar_url", nil},
		{"avatarUrl", "avatar_url", nil},
		{"bio", "bio", nil},
		{"identity.display_name", "", ErrUnknownPath},
		{"", "", ErrUnknownPath},
	}
	for _, tc := range cases {
		name := tc.raw
		if name == "" {
			name = "empty_raw"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := CanonicalGetProfileResponsePath(tc.raw)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err: got %v want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}
