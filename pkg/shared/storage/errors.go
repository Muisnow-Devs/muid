package storage

import "errors"

// ErrObjectNotFound indicates the object key does not exist in the bucket.
var ErrObjectNotFound = errors.New("storage: object not found")
