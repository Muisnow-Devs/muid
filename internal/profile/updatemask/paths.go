// Package updatemask implements FieldMask path normalization for profile partial updates.
// It depends only on generated protobuf types (no ent / DB imports) so it can be unit-tested safely.
package updatemask

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	pb "sanzi.io/muid/api/proto/profile/v1"
	claimspb "sanzi.io/muid/api/proto/shared/v1/claims"
)

// UpdateProfileRequest mask paths use proto snake_case with prefix:
//
//	identity.<field>  e.g. identity.email, identity.locale, identity.name, identity.username, identity.bio
//
// Patchable identity paths must be registered in profilegrpc.profilePatchRegistry; each path
// that publishes profile.change events also needs a GetProfileResponse segment below.
//
// Paths are relative to muid.profile.v1.UpdateProfileRequest (the identity field is optional;
// mutators still require a non-nil identity message when a masked path needs payload values).
//
// Clients using JSON may send camelCase in the second segment (e.g. identity.emailVerified);
// that is accepted and normalized to the canonical paths above.
const identityPrefix = "identity."

var (
	// ErrEmptyMask is returned when update_mask is nil or has no paths.
	ErrEmptyMask = errors.New("update_mask is empty")
	// ErrUnknownPath means the path is malformed or not a known protobuf field.
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
		return "", fmt.Errorf("%w: expected identity.<field>", ErrUnknownPath)
	}
	prefix := stringsTrimFold(parts[0])
	fieldTok := strings.TrimSpace(parts[1])
	if fieldTok == "" {
		return "", fmt.Errorf("%w: empty field segment", ErrUnknownPath)
	}
	if prefix != "identity" {
		return "", fmt.Errorf("%w: expected prefix %q", ErrUnknownPath, identityPrefix)
	}
	return canonicalDescriptorPath(
		identityPrefix,
		fieldTok,
		(&claimspb.IdentityInformation{}).ProtoReflect().Descriptor(),
	)
}

func stringsTrimFold(s string) string { return strings.TrimSpace(strings.ToLower(s)) }

func canonicalDescriptorPath(
	prefix, fieldTok string,
	md protoreflect.MessageDescriptor,
) (string, error) {
	for i := 0; i < md.Fields().Len(); i++ {
		f := md.Fields().Get(i)
		name := string(f.Name())
		if fieldTok == name || fieldTok == f.JSONName() || strings.EqualFold(fieldTok, name) ||
			strings.EqualFold(fieldTok, f.JSONName()) {
			return prefix + name, nil
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

// CanonicalGetProfileResponsePath returns the canonical proto field name for one path
// segment on GetProfileResponse (no dots). JSON camelCase aliases are accepted.
func CanonicalGetProfileResponsePath(raw string) (string, error) {
	p := strings.TrimSpace(raw)
	if p == "" {
		return "", fmt.Errorf("%w: empty path", ErrUnknownPath)
	}
	if strings.Contains(p, ".") {
		return "", fmt.Errorf("%w: expected a single path segment", ErrUnknownPath)
	}
	md := (&pb.GetProfileResponse{}).ProtoReflect().Descriptor()
	for i := 0; i < md.Fields().Len(); i++ {
		f := md.Fields().Get(i)
		name := string(f.Name())
		if p == name || p == f.JSONName() || strings.EqualFold(p, name) ||
			strings.EqualFold(p, f.JSONName()) {
			return name, nil
		}
	}
	return "", ErrUnknownPath
}

// SortedUniqueGetProfileResponsePaths validates, deduplicates, and sorts paths for
// ProfileChangedEvent.changed_fields (each path is one GetProfileResponse field).
func SortedUniqueGetProfileResponsePaths(raw []string) ([]string, error) {
	if len(raw) == 0 {
		return nil, ErrEmptyMask
	}
	seen := make(map[string]struct{}, len(raw))
	for _, r := range raw {
		canon, err := CanonicalGetProfileResponsePath(r)
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

func updateMaskPathToGetProfileSegment(canon string) (string, error) {
	canon = strings.TrimSpace(canon)
	switch {
	case strings.HasPrefix(canon, identityPrefix):
		switch strings.TrimPrefix(canon, identityPrefix) {
		case "email":
			return "email", nil
		case "locale":
			return "locale", nil
		case "timezone":
			return "timezone", nil
		case "username":
			return "username", nil
		case "name", "given_name", "family_name":
			return "display_name", nil
		case "picture":
			return "avatar_url", nil
		case "bio":
			return "bio", nil
		default:
			return "", fmt.Errorf(
				"%w: identity path %q has no GetProfileResponse mapping",
				ErrUnknownPath,
				canon,
			)
		}
	default:
		return "", fmt.Errorf("%w: path %q", ErrUnknownPath, canon)
	}
}

// GetProfileResponsePathsFromUpdateRequestPaths maps canonical UpdateProfileRequest mask
// paths (identity.*) to GetProfileResponse-relative names for profile.change events.
func GetProfileResponsePathsFromUpdateRequestPaths(updatePaths []string) ([]string, error) {
	if len(updatePaths) == 0 {
		return nil, ErrEmptyMask
	}
	raw := make([]string, 0, len(updatePaths))
	for _, p := range updatePaths {
		p = strings.TrimSpace(p)
		seg, err := updateMaskPathToGetProfileSegment(p)
		if err != nil {
			return nil, err
		}
		raw = append(raw, seg)
	}
	return SortedUniqueGetProfileResponsePaths(raw)
}
