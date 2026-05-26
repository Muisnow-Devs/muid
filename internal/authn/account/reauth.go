package account

import "time"

// ReauthenticationWindow is how long after session issuance sensitive operations
// may proceed without a fresh AUTH_INTENT_REAUTHENTICATE login.
const ReauthenticationWindow = 5 * time.Minute

// SessionRequiresReauthentication reports whether issuedAt is older than
// [ReauthenticationWindow] relative to now.
func SessionRequiresReauthentication(issuedAt, now time.Time) bool {
	return now.Sub(issuedAt.UTC()) > ReauthenticationWindow
}
