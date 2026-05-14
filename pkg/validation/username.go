package validation

import "regexp"

// UsernameCharsetRegex matches a username of 5–32 characters (inclusive) using
// only ASCII letters, digits, and underscore.
const UsernameCharsetRegex = `^[a-zA-Z0-9_]{5,32}$`

var usernameCharset = regexp.MustCompile(UsernameCharsetRegex)

// ValidUsername reports whether s is a permitted username (trim first if needed).
func ValidUsername(s string) bool {
	return usernameCharset.MatchString(s)
}
