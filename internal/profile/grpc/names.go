package profilegrpc

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"

	"sanzi.io/muid/pkg/errutil"
)

var adjectives = []string{
	"swift", "calm", "bright", "quiet", "gentle", "brave", "clever", "lucky", "noble", "wild",
	"cosmic", "silver", "golden", "azure", "crimson", "jade", "amber", "vivid", "stellar", "hidden",
}

var nouns = []string{
	"panda",
	"falcon",
	"river",
	"comet",
	"harbor",
	"meadow",
	"cipher",
	"atlas",
	"nova",
	"pixel",
	"orchid",
	"willow",
	"ember",
	"quartz",
	"nebula",
	"canvas",
	"beacon",
	"summit",
	"harvest",
	"voyage",
}

func randomDisplayName() string {
	var buf [8]byte
	_, err := rand.Read(buf[:])
	errutil.Discard(err)
	ai := binary.BigEndian.Uint32(buf[:4]) % uint32(len(adjectives))
	ni := binary.BigEndian.Uint32(buf[4:]) % uint32(len(nouns))
	var suffix [2]byte
	_, err = rand.Read(suffix[:])
	errutil.Discard(err)
	return fmt.Sprintf("%s-%s-%02x", adjectives[ai], nouns[ni], suffix[0])
}

// randomUsernameBase returns a fresh candidate username: prefix "user_" (5 runes)
// plus 8 lowercase hex digits (4 random bytes), total length 13 ∈ [5,16].
func randomUsernameBase() string {
	var b [4]byte
	_, err := rand.Read(b[:])
	errutil.Discard(err)
	return "user_" + hex.EncodeToString(b[:])
}

func generateUsernameCandidates(base string) []string {
	candidates := make([]string, 0, 56)

	candidates = append(candidates, base)

	for i := 1; i <= 24; i++ {
		candidates = append(
			candidates,
			base+"_"+strconv.Itoa(i),
		)
	}

	for i := 0; i < 32; i++ {
		candidates = append(
			candidates,
			randomUsernameBase(),
		)
	}

	return candidates
}
