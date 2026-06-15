package scripts

import (
	_ "embed"

	"github.com/go-redis/redis"
)

//go:embed compare_delete.lua
var luaCompareAndDeleteScript string
var CompareAndDeleteScript = redis.NewScript(luaCompareAndDeleteScript)

//go:embed increment_expire.lua
var luaIncrementAndExpireScript string

// IncrementAndExpireScript atomically increments KEYS[1] and, when it has no
// expiry yet, sets it to ARGV[1] milliseconds. It returns the new counter value.
var IncrementAndExpireScript = redis.NewScript(luaIncrementAndExpireScript)
