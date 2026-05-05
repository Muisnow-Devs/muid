package kv

import "errors"

var (
	ErrKeyNotFound = errors.New("kv: key not found")
	ErrInvalidKey  = errors.New("kv: invalid key")
	ErrStoreClosed = errors.New("kv: key-value store is closed")
)
