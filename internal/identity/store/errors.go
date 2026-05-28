package store

import "errors"

// ErrCredentialAlreadyRegistered is returned by PasskeyIdentityStore.LinkIdentity
// when the credential ID already exists in the database.
var ErrCredentialAlreadyRegistered = errors.New("store: passkey credential already registered")
