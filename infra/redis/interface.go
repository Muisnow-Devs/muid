// Package redis provides a Redis-backed implementation of [KVStore].
package redis

import "sanzi.io/muid/pkg/shared/kv"

// KVStore is the key-value contract implemented by [NewRedisKVStore].
type KVStore = kv.AtomicKVStore
