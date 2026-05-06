package kv

import "errors"

var (
	ErrKeyNotFound     = errors.New("kv: key not found")
	ErrInvalidKey      = errors.New("kv: invalid key")
	ErrPayloadTooLarge = errors.New("kv: payload too large")
	ErrStoreClosed     = errors.New("kv: key-value store is closed")
)
