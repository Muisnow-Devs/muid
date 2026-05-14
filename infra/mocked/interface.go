// Package mocked provides in-memory test doubles for infrastructure contracts.
package mocked

import "sanzi.io/muid/pkg/shared/kv"

// KVStore names the contract implemented by [NewMockKVStore].
type KVStore = kv.KVStore
