package core

import (
	"slices"
	"strings"

	"google.golang.org/protobuf/types/known/fieldmaskpb"

	idclaims "sanzi.io/muid/api/proto/shared/v1/claims"
	"sanzi.io/muid/internal/profile/ent"
	"sanzi.io/muid/internal/profile/updatemask"
	"sanzi.io/muid/pkg/localetime"
	"sanzi.io/muid/pkg/validation"
)

// fieldSpec fully describes one patchable UpdateProfile mask path: how to
// validate/normalize the requested value (parse, pure — no DB), how to apply
// it to the row (set), which GetProfileResponse field name it maps to in
// ProfileChangedEvent.changed_fields (responsePath), and how to copy the
// committed column into the event claims (claim). Adding an updatable scalar
// means one entry here plus buf validate rules on the proto field.
type fieldSpec struct {
	responsePath string
	parse        func(idn *idclaims.IdentityInformation) (string, error)
	set          func(u *ent.UserProfileUpdateOne, value string)
	claim        func(p *ent.UserProfile, c *idclaims.IdentityInformation)
}

// profileFields is the security allowlist: only these canonical mask paths run mutators.
var profileFields = map[string]fieldSpec{
	"identity.username": {
		responsePath: "username",
		parse:        parseUsername,
		set:          func(u *ent.UserProfileUpdateOne, v string) { u.SetUsername(v) },
		claim:        func(p *ent.UserProfile, c *idclaims.IdentityInformation) { c.SetUsername(p.Username) },
	},
	"identity.locale": {
		responsePath: "locale",
		parse:        parseLocale,
		set:          func(u *ent.UserProfileUpdateOne, v string) { u.SetLocale(v) },
		claim:        func(p *ent.UserProfile, c *idclaims.IdentityInformation) { c.SetLocale(p.Locale) },
	},
	"identity.timezone": {
		responsePath: "timezone",
		parse:        parseTimezone,
		set:          func(u *ent.UserProfileUpdateOne, v string) { u.SetTimezone(v) },
		claim: func(p *ent.UserProfile, c *idclaims.IdentityInformation) {
			c.SetTimezone(strings.TrimSpace(p.Timezone))
		},
	},
	"identity.name": {
		responsePath: "display_name",
		parse:        parseDisplayName,
		set:          func(u *ent.UserProfileUpdateOne, v string) { u.SetDisplayName(v) },
		claim:        func(p *ent.UserProfile, c *idclaims.IdentityInformation) { c.SetName(p.DisplayName) },
	},
	"identity.given_name": {
		responsePath: "display_name",
		parse:        parseDisplayName,
		set:          func(u *ent.UserProfileUpdateOne, v string) { u.SetDisplayName(v) },
		claim:        func(p *ent.UserProfile, c *idclaims.IdentityInformation) { c.SetName(p.DisplayName) },
	},
	"identity.family_name": {
		responsePath: "display_name",
		parse:        parseDisplayName,
		set:          func(u *ent.UserProfileUpdateOne, v string) { u.SetDisplayName(v) },
		claim:        func(p *ent.UserProfile, c *idclaims.IdentityInformation) { c.SetName(p.DisplayName) },
	},
	"identity.bio": {
		responsePath: "bio",
		parse:        parseBio,
		set:          func(u *ent.UserProfileUpdateOne, v string) { u.SetBiography(v) },
		claim: func(p *ent.UserProfile, c *idclaims.IdentityInformation) {
			c.SetBio(strings.TrimSpace(p.Biography))
		},
	},
}

func parseUsername(idn *idclaims.IdentityInformation) (string, error) {
	if idn == nil {
		return "", NewInvalidArgumentError("identity payload required for identity.username")
	}

	raw := strings.TrimSpace(idn.GetUsername())
	if raw == "" {
		return "", NewInvalidArgumentError("username must not be empty")
	}

	if !validation.ValidUsername(raw) {
		return "", NewInvalidArgumentError(
			"username must be 5-16 characters: lowercase letters, digits, underscore, period; cannot start with underscore or period",
		)
	}

	return strings.ToLower(raw), nil
}

func parseLocale(idn *idclaims.IdentityInformation) (string, error) {
	if idn == nil {
		return "", NewInvalidArgumentError("identity payload required for identity.locale")
	}

	loc := strings.TrimSpace(idn.GetLocale())
	if loc == "" {
		return "", NewInvalidArgumentError("locale must not be empty")
	}

	if len(loc) > 32 {
		return "", NewInvalidArgumentError("locale must be at most 32 characters")
	}

	return loc, nil
}

func parseTimezone(idn *idclaims.IdentityInformation) (string, error) {
	if idn == nil {
		return "", NewInvalidArgumentError("identity payload required for identity.timezone")
	}

	tz := strings.TrimSpace(idn.GetTimezone())
	if len(tz) > 64 {
		return "", NewInvalidArgumentError("timezone must be at most 64 characters")
	}
	if tz != "" && !localetime.ValidTimezone(tz) {
		return "", NewInvalidArgumentError("timezone must be a valid IANA time zone")
	}

	return tz, nil
}

func parseBio(idn *idclaims.IdentityInformation) (string, error) {
	if idn == nil {
		return "", NewInvalidArgumentError("identity payload required for identity.bio")
	}

	bio := strings.TrimSpace(idn.GetBio())
	if len(bio) > 1024 {
		return "", NewInvalidArgumentError("biography must be at most 1024 characters")
	}

	return bio, nil
}

func parseDisplayName(idn *idclaims.IdentityInformation) (string, error) {
	if idn == nil {
		return "", NewInvalidArgumentError(
			"identity payload required for display name identity paths",
		)
	}

	var name string
	if idn.GetName() != "" {
		name = strings.TrimSpace(idn.GetName())
	} else if idn.GetGivenName() != "" || idn.GetFamilyName() != "" {
		name = strings.TrimSpace(idn.GetGivenName() + " " + idn.GetFamilyName())
	}

	if name == "" {
		return "", NewInvalidArgumentError("no name fields provided for display name update")
	}

	return name, nil
}

// patchablePaths canonicalizes the mask and rejects paths outside the registry.
func patchablePaths(mask *fieldmaskpb.FieldMask) ([]string, error) {
	paths, err := updatemask.SortedUniqueCanonicalPaths(mask)
	if err != nil {
		return nil, err
	}

	for _, p := range paths {
		if _, ok := profileFields[p]; !ok {
			return nil, ErrUnsupportedMaskPath
		}
	}

	return paths, nil
}

// responsePathsFor maps applied mask paths to sorted-unique GetProfileResponse
// field names for ProfileChangedEvent.changed_fields.
func responsePathsFor(paths []string) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		rp := profileFields[p].responsePath
		if !slices.Contains(out, rp) {
			out = append(out, rp)
		}
	}
	slices.Sort(out)
	return out
}

// claimsFromSnapshot copies the committed columns named by responsePaths into
// event claims. Returns nil when nothing was set.
func claimsFromSnapshot(p *ent.UserProfile, responsePaths []string) *idclaims.IdentityInformation {
	if p == nil || len(responsePaths) == 0 {
		return nil
	}

	c := &idclaims.IdentityInformation{}
	done := make(map[string]struct{}, len(responsePaths))
	for _, spec := range profileFields {
		if _, dup := done[spec.responsePath]; dup {
			continue
		}
		if !slices.Contains(responsePaths, spec.responsePath) {
			continue
		}
		done[spec.responsePath] = struct{}{}
		spec.claim(p, c)
	}
	if len(done) == 0 {
		return nil
	}
	return c
}
