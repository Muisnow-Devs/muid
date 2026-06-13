package validation

import (
	"errors"
	"regexp"
)

// OrgSlugCharsetRegex matches an organization slug of 3–63 characters: lowercase
// letters, digits, and interior hyphens; the first and last character must be
// alphanumeric (no leading/trailing or doubled-edge hyphen).
const OrgSlugCharsetRegex = `^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`

var orgSlugCharset = regexp.MustCompile(OrgSlugCharsetRegex)

// ErrInvalidOrgSlug is returned by CheckOrgSlug when s is not permitted.
var ErrInvalidOrgSlug = errors.New("invalid organization slug")

// ValidOrgSlug reports whether s is a permitted organization slug (trim first if needed).
func ValidOrgSlug(s string) bool {
	return orgSlugCharset.MatchString(s)
}

// CheckOrgSlug returns nil when s is a permitted organization slug, otherwise ErrInvalidOrgSlug.
func CheckOrgSlug(s string) error {
	if !ValidOrgSlug(s) {
		return ErrInvalidOrgSlug
	}
	return nil
}
