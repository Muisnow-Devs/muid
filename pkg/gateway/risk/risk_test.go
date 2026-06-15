package risk_test

import (
	"context"
	"net/http"
	"testing"

	"sanzi.io/muid/pkg/gateway/risk"
)

func headers(ua string) http.Header {
	h := http.Header{}
	if ua != "" {
		h.Set("User-Agent", ua)
	}
	return h
}

func TestEvaluateDecisions(t *testing.T) {
	t.Parallel()

	eval := risk.NewEvaluator(risk.Config{
		PoWThreshold:     50,
		BlockThreshold:   90,
		BlockedCountries: []string{"xx"},
	})

	tests := []struct {
		name   string
		signal risk.Signal
		want   risk.Action
	}{
		{
			name:   "trusted authenticated user",
			signal: risk.Signal{Authenticated: true, RequestRate: 5, Headers: headers("Mozilla/5.0")},
			want:   risk.ActionAllow,
		},
		{
			name:   "anonymous normal traffic",
			signal: risk.Signal{RequestRate: 3, Headers: headers("curl/8")},
			want:   risk.ActionAllow,
		},
		{
			name:   "elevated brute force needs pow",
			signal: risk.Signal{RequestRate: 12, AuthFailures: 3, Headers: headers("Mozilla/5.0")},
			want:   risk.ActionRequirePoW,
		},
		{
			name:   "blocked country is blocked",
			signal: risk.Signal{RequestRate: 1, Headers: headers("Mozilla/5.0"), Geo: risk.Geo{Resolved: true, CountryCode: "XX"}},
			want:   risk.ActionBlock,
		},
		{
			name:   "high-volume brute force with no UA is blocked",
			signal: risk.Signal{RequestRate: 30, AuthFailures: 3, Headers: headers(""), Geo: risk.Geo{Resolved: true, CountryCode: "US"}},
			want:   risk.ActionBlock,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := eval.Evaluate(context.Background(), tc.signal)
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			if got.Action != tc.want {
				t.Fatalf("action = %v (score %d, reasons %v), want %v", got.Action, got.Score, got.Reasons, tc.want)
			}
		})
	}
}

func TestActionString(t *testing.T) {
	t.Parallel()
	cases := map[risk.Action]string{
		risk.ActionAllow:      "allow",
		risk.ActionRequirePoW: "require_pow",
		risk.ActionBlock:      "block",
	}
	for action, want := range cases {
		if action.String() != want {
			t.Errorf("Action(%d).String() = %q, want %q", action, action.String(), want)
		}
	}
}
