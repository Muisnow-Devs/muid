package grpcutils

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sony/gobreaker"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestShouldRetry(t *testing.T) {
	t.Parallel()

	retryable := codeSet(defaultRetryableCodes)

	tests := []struct {
		name string
		err  error
		ctx  context.Context
		want bool
	}{
		{name: "nil", err: nil, ctx: context.Background(), want: false},
		{
			name: "canceled context",
			err:  status.Error(codes.Unavailable, "x"),
			ctx:  canceledContext(t),
			want: false,
		},
		{
			name: "grpc canceled",
			err:  status.Error(codes.Canceled, "x"),
			ctx:  context.Background(),
			want: false,
		},
		{
			name: "unavailable",
			err:  status.Error(codes.Unavailable, "x"),
			ctx:  context.Background(),
			want: true,
		},
		{
			name: "deadline exceeded",
			err:  status.Error(codes.DeadlineExceeded, "x"),
			ctx:  context.Background(),
			want: true,
		},
		{
			name: "resource exhausted",
			err:  status.Error(codes.ResourceExhausted, "x"),
			ctx:  context.Background(),
			want: true,
		},
		{
			name: "invalid argument",
			err:  status.Error(codes.InvalidArgument, "x"),
			ctx:  context.Background(),
			want: false,
		},
		{name: "non grpc", err: errors.New("network"), ctx: context.Background(), want: false},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := tc.ctx
			if ctx == nil {
				ctx = context.Background()
			}
			if got := shouldRetry(ctx, tc.err, retryable); got != tc.want {
				t.Fatalf("shouldRetry() = %v, want %v", got, tc.want)
			}
		})
	}
}

func canceledContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func TestRetryDelay(t *testing.T) {
	t.Parallel()

	cfg := RetryConfig{
		BaseBackoff: 100 * time.Millisecond,
		MaxBackoff:  500 * time.Millisecond,
	}

	tests := []struct {
		retryIndex int
		want       time.Duration
	}{
		{retryIndex: 1, want: 100 * time.Millisecond},
		{retryIndex: 2, want: 200 * time.Millisecond},
		{retryIndex: 3, want: 400 * time.Millisecond},
		{retryIndex: 4, want: 500 * time.Millisecond},
	}

	for _, tc := range tests {
		tc := tc
		t.Run("", func(t *testing.T) {
			t.Parallel()
			if got := retryDelay(cfg, tc.retryIndex); got != tc.want {
				t.Fatalf("retryDelay(%d) = %v, want %v", tc.retryIndex, got, tc.want)
			}
		})
	}
}

func TestWaitRetryRespectsCancel(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := waitRetry(ctx, time.Second); !errors.Is(err, context.Canceled) {
		t.Fatalf("waitRetry() = %v, want context.Canceled", err)
	}
}

func TestUnaryRetryInterceptorAttempts(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	invoker := func(context.Context, string, any, any, *grpc.ClientConn, ...grpc.CallOption) error {
		n := calls.Add(1)
		if n < 3 {
			return status.Error(codes.Unavailable, "try again")
		}
		return nil
	}

	ic := UnaryRetryInterceptor(RetryConfig{
		MaxRetries:     2,
		BaseBackoff:    time.Millisecond,
		MaxBackoff:     time.Millisecond,
		RetryableCodes: defaultRetryableCodes,
	})

	err := ic(context.Background(), "/test", nil, nil, nil, invoker)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("calls = %d, want 3", got)
	}
}

func TestUnaryCircuitBreakerInterceptorOpen(t *testing.T) {
	t.Parallel()

	cb := gobreaker.NewCircuitBreaker(gobreaker.Settings{
		Name:        "test",
		MaxRequests: 1,
		Timeout:     time.Minute,
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			return counts.ConsecutiveFailures >= 1
		},
	})

	ic := UnaryCircuitBreakerInterceptor(cb)
	fail := func(context.Context, string, any, any, *grpc.ClientConn, ...grpc.CallOption) error {
		return status.Error(codes.Unavailable, "down")
	}

	_ = ic(context.Background(), "/test", nil, nil, nil, fail)

	err := ic(context.Background(), "/test", nil, nil, nil, fail)
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable", status.Code(err))
	}
	if status.Convert(err).Message() != "dependency circuit open" {
		t.Fatalf("message = %q", status.Convert(err).Message())
	}
}

func TestDialInsecureClientEmptyTarget(t *testing.T) {
	t.Parallel()

	_, err := DialInsecureClient("  ", DefaultClientResilienceConfig())
	if err == nil {
		t.Fatal("expected error for empty target")
	}
}
