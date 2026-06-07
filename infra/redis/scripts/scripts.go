package scripts

import (
	_ "embed"

	"github.com/go-redis/redis"
)

//go:embed compare_delete.lua
var luaCompareAndDeleteScript string
var CompareAndDeleteScript = redis.NewScript(luaCompareAndDeleteScript)
