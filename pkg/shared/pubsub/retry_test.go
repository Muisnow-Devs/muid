package pubsub

import (
	"testing"
	"time"
)

type testHeaders map[string]string

func (h testHeaders) Get(key string) string { return h[key] }
func (h testHeaders) Set(key, value string) { h[key] = value }

func TestRetryPolicyHeaders(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		policy     RetryPolicy
		want       RetryPolicy
		wantFound  bool
		wantErr    bool
		beforeRead func(testHeaders)
	}{
		{
			name:      "missing headers use defaults",
			want:      DefaultRetryPolicy(),
			wantFound: false,
		},
		{
			name: "encode and decode explicit policy",
			policy: RetryPolicy{
				MaxAttempts:       7,
				InitialDelay:      2 * time.Second,
				MaxDelay:          time.Minute,
				BackoffMultiplier: 1.5,
			},
			want: RetryPolicy{
				MaxAttempts:       7,
				InitialDelay:      2 * time.Second,
				MaxDelay:          time.Minute,
				BackoffMultiplier: 1.5,
			},
			wantFound: true,
		},
		{
			name: "zero policy encodes defaults",
			want: DefaultRetryPolicy(),
			beforeRead: func(headers testHeaders) {
				EncodeRetryPolicyHeaders(headers, RetryPolicy{})
			},
			wantFound: true,
		},
		{
			name: "bad max attempts reports error",
			beforeRead: func(headers testHeaders) {
				EncodeRetryPolicyHeaders(headers, DefaultRetryPolicy())
				headers.Set(RetryMaxAttemptsHeader, "bad")
			},
			wantFound: true,
			wantErr:   true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			headers := testHeaders{}
			if tc.policy != (RetryPolicy{}) {
				EncodeRetryPolicyHeaders(headers, tc.policy)
			}
			if tc.beforeRead != nil {
				tc.beforeRead(headers)
			}

			got, found, err := DecodeRetryPolicyHeaders(headers)
			if tc.wantErr {
				if err == nil {
					t.Fatal("DecodeRetryPolicyHeaders() expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("DecodeRetryPolicyHeaders() unexpected error: %v", err)
			}
			if found != tc.wantFound {
				t.Fatalf("DecodeRetryPolicyHeaders() found = %v, want %v", found, tc.wantFound)
			}
			if got != tc.want {
				t.Fatalf("DecodeRetryPolicyHeaders() = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestRetryPolicyDefaultsAndBackoff(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		policy  RetryPolicy
		attempt uint64
		want    time.Duration
	}{
		{
			name: "first failure uses initial delay",
			policy: RetryPolicy{
				MaxAttempts:       3,
				InitialDelay:      time.Second,
				MaxDelay:          10 * time.Second,
				BackoffMultiplier: 2,
			},
			attempt: 1,
			want:    time.Second,
		},
		{
			name: "later failure backs off",
			policy: RetryPolicy{
				MaxAttempts:       3,
				InitialDelay:      time.Second,
				MaxDelay:          10 * time.Second,
				BackoffMultiplier: 2,
			},
			attempt: 3,
			want:    4 * time.Second,
		},
		{
			name: "delay is capped",
			policy: RetryPolicy{
				MaxAttempts:       5,
				InitialDelay:      time.Second,
				MaxDelay:          3 * time.Second,
				BackoffMultiplier: 2,
			},
			attempt: 4,
			want:    3 * time.Second,
		},
		{
			name:    "empty policy uses default initial delay",
			policy:  RetryPolicy{},
			attempt: 1,
			want:    DefaultRetryPolicy().InitialDelay,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := tc.policy.DelayForAttempt(tc.attempt)
			if got != tc.want {
				t.Fatalf("DelayForAttempt() = %v, want %v", got, tc.want)
			}
		})
	}
}
