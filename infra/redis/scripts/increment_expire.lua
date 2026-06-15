-- Atomically increment a counter and set its TTL when it has none yet.
-- KEYS[1]: counter key. ARGV[1]: ttl in milliseconds.
-- Returns the new counter value. Setting the TTL only when missing keeps
-- fixed-window semantics (it is not refreshed on every increment) and
-- self-heals a key that was somehow left without an expiry.
local count = redis.call("INCR", KEYS[1])
if redis.call("PTTL", KEYS[1]) < 0 then
    redis.call("PEXPIRE", KEYS[1], ARGV[1])
end
return count
