// Package errutil holds small helpers for error handling at intentional discard sites.
package errutil

// Discard intentionally ignores an error (e.g. defer Close/Rollback after failure paths).
// Do not use to hide errors that callers should handle or log.
func Discard(err error) {
	_ = err
}
