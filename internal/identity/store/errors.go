package store

import "errors"

// ErrIdentityAlreadyLinked is returned by any IdentityStore.LinkIdentity
// implementation when the identity being linked already exists in the database
// (detected via a unique-constraint violation on INSERT, not a pre-flight query).
var ErrIdentityAlreadyLinked = errors.New("store: identity already linked")
