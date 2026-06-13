package core

import (
	"crypto/rand"
	"encoding/hex"
	"regexp"
	"strconv"
	"strings"

	"sanzi.io/muid/pkg/errutil"
)

// orgSlugSeparators collapses any run of non-[a-z0-9] characters to a single hyphen.
var orgSlugSeparators = regexp.MustCompile(`[^a-z0-9]+`)

// maxSlugBase leaves room for a "-NN" disambiguating suffix within the 63-char
// slug budget enforced by validation.ValidOrgSlug.
const maxSlugBase = 48

// slugifyDisplayName derives a base slug from a display name: lowercased, with
// non-alphanumeric runs collapsed to single hyphens and edges trimmed. When
// nothing usable remains (or the result is too short) it returns a random base.
func slugifyDisplayName(name string) string {
	s := strings.ToLower(strings.TrimSpace(name))
	s = orgSlugSeparators.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if len(s) > maxSlugBase {
		s = strings.Trim(s[:maxSlugBase], "-")
	}
	if len(s) < 3 {
		return randomSlugBase()
	}
	return s
}

// randomSlugBase returns a fresh candidate slug: prefix "org-" plus 8 lowercase
// hex digits (4 random bytes), total length 12 — always a valid slug.
func randomSlugBase() string {
	var b [4]byte
	_, err := rand.Read(b[:])
	errutil.Discard(err)
	return "org-" + hex.EncodeToString(b[:])
}

// generateSlugCandidates yields the base slug, then numeric-suffixed variants,
// then random fallbacks — mirroring generateUsernameCandidates.
func generateSlugCandidates(base string) []string {
	candidates := make([]string, 0, 56)

	candidates = append(candidates, base)

	for i := 2; i <= 25; i++ {
		candidates = append(candidates, base+"-"+strconv.Itoa(i))
	}

	for range 32 {
		candidates = append(candidates, randomSlugBase())
	}

	return candidates
}
