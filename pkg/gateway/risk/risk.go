// Package risk implements the gateway risk model. An Evaluator turns a Signal
// (request rate, auth state, recent auth failures, headers, IP, geo) into a
// Decision: allow the request, demand a proof-of-work challenge, or block it.
//
// The scoring policy is an interface (Scorer) so it can evolve without changing
// callers; the default HeuristicScorer is pure logic and has no I/O, keeping it
// trivially testable. Redis-backed counters that populate a Signal live in
// tracker.go.
package risk

import (
	"context"
	"net/http"
	"sort"
	"strings"
)

// Action is the gateway's enforcement choice for a request.
type Action int

const (
	// ActionAllow lets the request proceed.
	ActionAllow Action = iota
	// ActionRequirePoW demands the caller solve a proof-of-work challenge.
	ActionRequirePoW
	// ActionBlock rejects the request outright.
	ActionBlock
)

func (a Action) String() string {
	switch a {
	case ActionAllow:
		return "allow"
	case ActionRequirePoW:
		return "require_pow"
	case ActionBlock:
		return "block"
	default:
		return "unknown"
	}
}

// Geo carries the IP-resolution facts the scorer cares about. It mirrors a
// subset of infra/geoip.GeoInfo to avoid coupling the model to the driver.
type Geo struct {
	CountryCode string
	Resolved    bool
}

// Signal is the full set of inputs to a risk evaluation. Counters (RequestRate,
// AuthFailures) are typically filled by a Tracker; the rest by the gateway's
// request middleware.
type Signal struct {
	IP            string
	Authenticated bool
	RequestRate   int
	AuthFailures  int
	Headers       http.Header
	Geo           Geo
}

// Decision is the evaluation outcome.
type Decision struct {
	Action  Action
	Score   int
	Reasons []string
}

// Scorer maps a Signal to a numeric risk score and human-readable reasons.
type Scorer interface {
	Score(Signal) (int, []string)
}

// Config tunes the thresholds at which scores escalate to PoW or a block.
type Config struct {
	// PoWThreshold is the inclusive score at which ActionRequirePoW kicks in.
	PoWThreshold int
	// BlockThreshold is the inclusive score at which ActionBlock kicks in.
	BlockThreshold int
	// Scorer overrides the default HeuristicScorer when non-nil.
	Scorer Scorer
	// BlockedCountries is consulted by the default scorer (ISO 3166-1 alpha-2).
	BlockedCountries []string
}

// Evaluator applies a Scorer and the configured thresholds.
type Evaluator struct {
	scorer  Scorer
	powAt   int
	blockAt int
}

// NewEvaluator builds an Evaluator, applying default thresholds and scorer.
func NewEvaluator(cfg Config) *Evaluator {
	if cfg.PoWThreshold <= 0 {
		cfg.PoWThreshold = 50
	}
	if cfg.BlockThreshold <= 0 {
		cfg.BlockThreshold = 90
	}
	scorer := cfg.Scorer
	if scorer == nil {
		scorer = NewHeuristicScorer(cfg.BlockedCountries)
	}
	return &Evaluator{
		scorer:  scorer,
		powAt:   cfg.PoWThreshold,
		blockAt: cfg.BlockThreshold,
	}
}

// Evaluate scores the signal and selects an action from the thresholds.
func (e *Evaluator) Evaluate(_ context.Context, sig Signal) (Decision, error) {
	score, reasons := e.scorer.Score(sig)
	decision := Decision{Score: score, Reasons: reasons, Action: ActionAllow}
	switch {
	case score >= e.blockAt:
		decision.Action = ActionBlock
	case score >= e.powAt:
		decision.Action = ActionRequirePoW
	}
	return decision, nil
}

// HeuristicScorer is the default, dependency-free scoring policy.
type HeuristicScorer struct {
	blockedCountries map[string]struct{}
}

// NewHeuristicScorer builds a HeuristicScorer. blockedCountries are upper-cased
// ISO 3166-1 alpha-2 codes that score heavily.
func NewHeuristicScorer(blockedCountries []string) *HeuristicScorer {
	set := make(map[string]struct{}, len(blockedCountries))
	for _, c := range blockedCountries {
		if c = strings.ToUpper(strings.TrimSpace(c)); c != "" {
			set[c] = struct{}{}
		}
	}
	return &HeuristicScorer{blockedCountries: set}
}

// Score implements Scorer with a small additive heuristic.
func (h *HeuristicScorer) Score(sig Signal) (int, []string) {
	score := 0
	reasons := make([]string, 0, 4)

	// Authenticated callers start with a trust discount.
	if sig.Authenticated {
		score -= 20
	}

	// Request-rate pressure: each request beyond 10 in the window adds risk.
	if over := sig.RequestRate - 10; over > 0 {
		score += min(over*3, 60)
		reasons = append(reasons, "high_request_rate")
	}

	// Repeated auth failures are a strong brute-force indicator.
	if sig.AuthFailures > 0 {
		score += min(sig.AuthFailures*15, 80)
		reasons = append(reasons, "auth_failures")
	}

	// Missing User-Agent is a common bot tell.
	if ua := strings.TrimSpace(sig.Headers.Get("User-Agent")); ua == "" {
		score += 25
		reasons = append(reasons, "missing_user_agent")
	}

	// Blocked geographies are an outright signal.
	if sig.Geo.Resolved && sig.Geo.CountryCode != "" {
		if _, blocked := h.blockedCountries[strings.ToUpper(sig.Geo.CountryCode)]; blocked {
			score += 100
			reasons = append(reasons, "blocked_country")
		}
	}

	if score < 0 {
		score = 0
	}
	sort.Strings(reasons)
	return score, reasons
}
