// Package pow implements a Hashcash-style proof-of-work challenge used by the
// risk model's RequirePoW decision. Challenges are single-use: redemption is an
// atomic CompareAndDelete on the shared kv store, the same anti-replay primitive
// the OIDC code store relies on (internal/authn/oidc/store/code_store.go).
package pow

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"

	"sanzi.io/muid/pkg/shared/kv"
)

var (
	// ErrUnknownChallenge means the challenge id was never issued, already
	// redeemed, or expired.
	ErrUnknownChallenge = errors.New("pow: unknown challenge")
	// ErrInvalidSolution means the supplied solution does not satisfy the
	// required difficulty for the challenge seed.
	ErrInvalidSolution = errors.New("pow: invalid solution")
)

// Config parameterises issued challenges.
type Config struct {
	// Difficulty is the number of leading zero bits required of the solution
	// hash. Defaults to 20 when <= 0.
	Difficulty int
	// TTL bounds how long a challenge remains solvable. Defaults to 2m.
	TTL time.Duration
}

// Challenge is handed to the client, which must find a Solution whose hash over
// Seed has at least Difficulty leading zero bits.
type Challenge struct {
	ID         string `json:"id"`
	Seed       string `json:"seed"`
	Difficulty int    `json:"difficulty"`
}

// Manager issues and verifies challenges against a kv store.
type Manager struct {
	store      kv.AtomicKVStore
	difficulty int
	ttl        time.Duration
}

// New builds a Manager.
func New(store kv.AtomicKVStore, cfg Config) *Manager {
	if cfg.Difficulty <= 0 {
		cfg.Difficulty = 20
	}
	if cfg.TTL <= 0 {
		cfg.TTL = 2 * time.Minute
	}
	return &Manager{store: store, difficulty: cfg.Difficulty, ttl: cfg.TTL}
}

// Issue mints a fresh challenge and stores its seed for single-use redemption.
func (m *Manager) Issue(ctx context.Context) (Challenge, error) {
	id, err := randomHex(16)
	if err != nil {
		return Challenge{}, err
	}
	seed, err := randomHex(16)
	if err != nil {
		return Challenge{}, err
	}
	// Persist the seed with the difficulty in force at issue time so Verify uses
	// the challenge's own difficulty, not a later-changed config value.
	stored := seed + ":" + strconv.Itoa(m.difficulty)
	if err := m.store.Set(ctx, m.key(id), []byte(stored), m.ttl); err != nil {
		return Challenge{}, err
	}
	return Challenge{ID: id, Seed: seed, Difficulty: m.difficulty}, nil
}

// Verify checks that solution satisfies the challenge and atomically redeems it,
// preventing reuse. Returns ErrUnknownChallenge or ErrInvalidSolution on failure.
func (m *Manager) Verify(ctx context.Context, challengeID, solution string) error {
	challengeID = strings.TrimSpace(challengeID)
	solution = strings.TrimSpace(solution)
	if challengeID == "" || solution == "" {
		return ErrInvalidSolution
	}

	stored, err := m.store.Get(ctx, m.key(challengeID))
	if err != nil {
		if errors.Is(err, kv.ErrKeyNotFound) {
			return ErrUnknownChallenge
		}
		return err
	}

	seed, difficulty, ok := parseStored(string(stored))
	if !ok {
		return ErrUnknownChallenge
	}
	if !satisfiesDifficulty(seed, solution, difficulty) {
		return ErrInvalidSolution
	}

	// Atomic redemption against the exact stored value: only the first valid
	// solver wins.
	deleted, err := m.store.CompareAndDelete(ctx, m.key(challengeID), stored)
	if err != nil {
		return err
	}
	if !deleted {
		return ErrUnknownChallenge
	}
	return nil
}

// parseStored splits the persisted "<seed>:<difficulty>" challenge value.
func parseStored(stored string) (seed string, difficulty int, ok bool) {
	seed, diffStr, found := strings.Cut(stored, ":")
	if !found {
		return "", 0, false
	}
	d, err := strconv.Atoi(diffStr)
	if err != nil || d <= 0 {
		return "", 0, false
	}
	return seed, d, true
}

func (m *Manager) key(id string) string {
	return "muid:pow:" + id
}

// satisfiesDifficulty reports whether sha256(seed || ":" || solution) has at
// least difficulty leading zero bits.
func satisfiesDifficulty(seed, solution string, difficulty int) bool {
	sum := sha256.Sum256([]byte(seed + ":" + solution))
	return leadingZeroBits(sum[:]) >= difficulty
}

func leadingZeroBits(b []byte) int {
	count := 0
	for _, by := range b {
		if by == 0 {
			count += 8
			continue
		}
		for bit := 7; bit >= 0; bit-- {
			if by&(1<<uint(bit)) == 0 {
				count++
			} else {
				return count
			}
		}
		break
	}
	return count
}

func randomHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
