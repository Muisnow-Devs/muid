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
		{"profile.display_name", "profile.display_name", nil},
		{" profile.displayName ", "profile.display_name", nil},
		{"PROFILE.USERNAME", "profile.username", nil},
		{"profile.locale", "profile.locale", nil},
		{"profile.display_name.extra", "", ErrUnknownPath},
		{"display_name", "", ErrUnknownPath},
		{"user.display_name", "", ErrUnknownPath},
		{"profile.nope", "", ErrUnknownPath},
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
			Paths: []string{"profile.locale", "profile.displayName", "profile.display_name"},
		}
		got, err := SortedUniqueCanonicalPaths(mask)
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"profile.display_name", "profile.locale"}
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
