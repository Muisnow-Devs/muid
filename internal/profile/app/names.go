package app

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/google/uuid"
)

var adjectives = []string{
	"swift", "calm", "bright", "quiet", "gentle", "brave", "clever", "lucky", "noble", "wild",
	"cosmic", "silver", "golden", "azure", "crimson", "jade", "amber", "vivid", "stellar", "hidden",
}

var nouns = []string{
	"panda", "falcon", "river", "comet", "harbor", "meadow", "cipher", "atlas", "nova", "pixel",
	"orchid", "willow", "ember", "quartz", "nebula", "canvas", "beacon", "summit", "harvest", "voyage",
}

func randomDisplayName() string {
	var buf [8]byte
	_, _ = rand.Read(buf[:])
	ai := binary.BigEndian.Uint32(buf[:4]) % uint32(len(adjectives))
	ni := binary.BigEndian.Uint32(buf[4:]) % uint32(len(nouns))
	var suffix [2]byte
	_, _ = rand.Read(suffix[:])
	return fmt.Sprintf("%s-%s-%02x", adjectives[ai], nouns[ni], suffix[0])
}

func randomUsernameBase() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return "user-" + hex.EncodeToString(b[:])
}

func githubIdenticonURL(profileID uuid.UUID) string {
	sum := sha256.Sum256(profileID[:])
	h := hex.EncodeToString(sum[:])
	return fmt.Sprintf("https://github.com/identicons/%s.png", h[:20])
}
