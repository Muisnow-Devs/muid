// Package turnstile verifies Cloudflare Turnstile CAPTCHA tokens. Only exported
// interfaces and config live here; the HTTP implementation is in turnstile.go,
// the test double in mock.go, and stable errors in errors.go.
package turnstile

import "context"

// Result is the outcome of a siteverify call.
type Result struct {
	Success     bool
	ErrorCodes  []string
	ChallengeTS string
	Hostname    string
	Action      string
}

// Verifier validates a Turnstile response token, optionally binding it to the
// caller's remote IP.
type Verifier interface {
	Verify(ctx context.Context, token, remoteIP string) (Result, error)
}
