// Package updatemask implements FieldMask path normalization for profile partial updates.
// It depends only on generated protobuf types (no ent / DB imports) so it can be unit-tested safely.
package updatemask

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"google.golang.org/protobuf/types/known/fieldmaskpb"

	pb "sanzi.io/muid/api/proto/profile/v1"
)

// Profile update_mask paths are relative to UpdateProfileRequest. The canonical internal
// form is proto snake_case with the nested message segment:
//
//	profile.<field snake_name>   e.g. profile.display_name, profile.locale
//
// Clients using JSON may send camelCase in the second segment (e.g. profile.displayName);
// that is accepted and normalized to the canonical paths above.
const profilePrefix = "profile."

var (
	// ErrEmptyMask is returned when update_mask is nil or has no paths.
	ErrEmptyMask = errors.New("update_mask is empty")
	// ErrUnknownPath means the path is malformed or not a field on UpdateProfileFields.
	ErrUnknownPath = errors.New("unknown update_mask path")
)

// CanonicalProfilePath returns the canonical allowlisted path for one mask entry,
// or ErrUnknownPath when the path is malformed or not a known protobuf field.
func CanonicalProfilePath(raw string) (string, error) {
	p := strings.TrimSpace(raw)
	if p == "" {
		return "", fmt.Errorf("%w: empty path", ErrUnknownPath)
	}
	parts := strings.Split(p, ".")
	if len(parts) != 2 {
		return "", fmt.Errorf("%w: expected <profile>.<field>", ErrUnknownPath)
	}
	if !strings.EqualFold(parts[0], "profile") {
		return "", fmt.Errorf("%w: expected prefix %q", ErrUnknownPath, profilePrefix)
	}
	fieldTok := strings.TrimSpace(parts[1])
	if fieldTok == "" {
		return "", fmt.Errorf("%w: empty field segment", ErrUnknownPath)
	}
	md := (&pb.UpdateProfileFields{}).ProtoReflect().Descriptor()
	for i := 0; i < md.Fields().Len(); i++ {
		f := md.Fields().Get(i)
		name := string(f.Name())
		if fieldTok == name || fieldTok == f.JSONName() || strings.EqualFold(fieldTok, name) || strings.EqualFold(fieldTok, f.JSONName()) {
			return profilePrefix + name, nil
		}
	}
	return "", ErrUnknownPath
}

// SortedUniqueCanonicalPaths validates and normalizes FieldMask paths for UpdateProfile.
// Empty or nil mask returns ErrEmptyMask. Unknown paths return ErrUnknownPath.
func SortedUniqueCanonicalPaths(mask *fieldmaskpb.FieldMask) ([]string, error) {
	if mask == nil || len(mask.GetPaths()) == 0 {
		return nil, ErrEmptyMask
	}
	seen := make(map[string]struct{}, len(mask.GetPaths()))
	for _, raw := range mask.GetPaths() {
		canon, err := CanonicalProfilePath(raw)
		if err != nil {
			return nil, err
		}
		seen[canon] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out, nil
}
