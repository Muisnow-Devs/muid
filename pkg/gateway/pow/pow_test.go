package pow_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"strconv"
	"testing"
	"time"

	"sanzi.io/muid/infra/mocked"
	"sanzi.io/muid/pkg/gateway/pow"
)

// solve brute-forces a solution for the challenge (small difficulty in tests).
func solve(t *testing.T, c pow.Challenge) string {
	t.Helper()
	for i := range 1 << 24 {
		candidate := strconv.Itoa(i)
		sum := sha256.Sum256([]byte(c.Seed + ":" + candidate))
		if leadingZeroBits(sum[:]) >= c.Difficulty {
			return candidate
		}
	}
	t.Fatalf("no solution found for difficulty %d", c.Difficulty)
	return ""
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

func TestIssueAndVerify(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	mgr := pow.New(mocked.NewMockKVStore(), pow.Config{Difficulty: 8, TTL: time.Minute})

	ch, err := mgr.Issue(ctx)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if ch.ID == "" || ch.Seed == "" || ch.Difficulty != 8 {
		t.Fatalf("unexpected challenge: %+v", ch)
	}

	solution := solve(t, ch)
	if err := mgr.Verify(ctx, ch.ID, solution); err != nil {
		t.Fatalf("Verify valid solution: %v", err)
	}

	// Single-use: re-verifying the redeemed challenge must fail.
	if err := mgr.Verify(ctx, ch.ID, solution); !errors.Is(err, pow.ErrUnknownChallenge) {
		t.Fatalf("replay should yield ErrUnknownChallenge, got %v", err)
	}
}

func TestVerifyInvalidSolution(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	mgr := pow.New(mocked.NewMockKVStore(), pow.Config{Difficulty: 16, TTL: time.Minute})

	ch, err := mgr.Issue(ctx)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := mgr.Verify(ctx, ch.ID, "definitely-wrong"); !errors.Is(err, pow.ErrInvalidSolution) {
		t.Fatalf("expected ErrInvalidSolution, got %v", err)
	}
}

func TestVerifyUnknownChallenge(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	mgr := pow.New(mocked.NewMockKVStore(), pow.Config{Difficulty: 8, TTL: time.Minute})

	if err := mgr.Verify(ctx, "nope", "0"); !errors.Is(err, pow.ErrUnknownChallenge) {
		t.Fatalf("expected ErrUnknownChallenge, got %v", err)
	}
}
