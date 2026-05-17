package validation

import (
	"errors"
	"regexp"
)

// UsernameCharsetRegex matches a username of 5–16 characters (inclusive): lowercase
// letters, digits, underscore, and period; the first character must not be _ or .
const UsernameCharsetRegex = `^[a-z0-9][a-z0-9_.]{4,15}$`

var usernameCharset = regexp.MustCompile(UsernameCharsetRegex)

// ErrInvalidUsername is returned by CheckUsername when s is not permitted.
var ErrInvalidUsername = errors.New("invalid username")

// ValidUsername reports whether s is a permitted username (trim first if needed).
func ValidUsername(s string) bool {
	return usernameCharset.MatchString(s)
}

// CheckUsername returns nil when s is a permitted username, otherwise ErrInvalidUsername.
func CheckUsername(s string) error {
	if !ValidUsername(s) {
		return ErrInvalidUsername
	}
	return nil
}
