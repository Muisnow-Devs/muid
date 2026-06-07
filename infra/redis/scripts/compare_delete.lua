local value = redis.call("GET", KEYS[1])

if not value then
    return 0
end

if value == ARGV[1] then
    redis.call("DEL", KEYS[1])
    return 1
end

return 0
