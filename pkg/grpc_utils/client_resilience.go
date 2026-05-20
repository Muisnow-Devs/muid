package grpcutils

import (
	"context"
	"errors"
	"time"

	"github.com/sony/gobreaker"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Default transient gRPC codes for outbound unary retry.
var defaultRetryableCodes = []codes.Code{
	codes.Unavailable,
	codes.DeadlineExceeded,
	codes.ResourceExhausted,
}

// RetryConfig bounds unary client retries for transient failures.
type RetryConfig struct {
	// MaxRetries is the number of retries after the first attempt (0 disables retry).
	MaxRetries int
	// BaseBackoff is the delay before the first retry; later retries use exponential growth.
	BaseBackoff time.Duration
	// MaxBackoff caps per-attempt wait.
	MaxBackoff time.Duration
	// RetryableCodes overrides the default transient code set when non-empty.
	RetryableCodes []codes.Code
}

// DefaultRetryConfig is used when RetryConfig fields are zero.
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxRetries:     2,
		BaseBackoff:    100 * time.Millisecond,
		MaxBackoff:     2 * time.Second,
		RetryableCodes: defaultRetryableCodes,
	}
}

func (c RetryConfig) withDefaults() RetryConfig {
	if c.MaxRetries < 0 {
		c.MaxRetries = 0
	}
	d := DefaultRetryConfig()
	if c.BaseBackoff <= 0 {
		c.BaseBackoff = d.BaseBackoff
	}
	if c.MaxBackoff <= 0 {
		c.MaxBackoff = d.MaxBackoff
	}
	if len(c.RetryableCodes) == 0 {
		c.RetryableCodes = d.RetryableCodes
	}
	return c
}

// CircuitBreakerConfig configures a gobreaker circuit for outbound unary calls.
type CircuitBreakerConfig struct {
	Enabled bool
	// Name labels the breaker (metrics/logs); defaults to "grpc-client" when empty.
	Name string
	// MaxRequests is the permitted calls in half-open state.
	MaxRequests uint32
	// Interval resets failure counts in closed state.
	Interval time.Duration
	// OpenTimeout is how long the breaker stays open before half-open.
	OpenTimeout time.Duration
	// ConsecutiveFailures trips the breaker from closed to open.
	ConsecutiveFailures uint32
}

// DefaultCircuitBreakerConfig is used when CircuitBreakerConfig fields are zero.
func DefaultCircuitBreakerConfig() CircuitBreakerConfig {
	return CircuitBreakerConfig{
		Enabled:             true,
		Name:                "grpc-client",
		MaxRequests:         3,
		Interval:            60 * time.Second,
		OpenTimeout:         30 * time.Second,
		ConsecutiveFailures: 5,
	}
}

func (c CircuitBreakerConfig) withDefaults() CircuitBreakerConfig {
	d := DefaultCircuitBreakerConfig()
	if !c.Enabled {
		return c
	}
	if c.Name == "" {
		c.Name = d.Name
	}
	if c.MaxRequests == 0 {
		c.MaxRequests = d.MaxRequests
	}
	if c.Interval <= 0 {
		c.Interval = d.Interval
	}
	if c.OpenTimeout <= 0 {
		c.OpenTimeout = d.OpenTimeout
	}
	if c.ConsecutiveFailures == 0 {
		c.ConsecutiveFailures = d.ConsecutiveFailures
	}
	return c
}

// ClientResilienceConfig groups retry and circuit breaker settings for service clients.
type ClientResilienceConfig struct {
	Retry          RetryConfig
	CircuitBreaker CircuitBreakerConfig
}

// DefaultClientResilienceConfig enables retry and circuit breaker with library defaults.
func DefaultClientResilienceConfig() ClientResilienceConfig {
	return ClientResilienceConfig{
		Retry:          DefaultRetryConfig(),
		CircuitBreaker: DefaultCircuitBreakerConfig(),
	}
}

// NewCircuitBreaker builds a gobreaker from cfg (defaults applied).
func NewCircuitBreaker(cfg CircuitBreakerConfig) *gobreaker.CircuitBreaker {
	cfg = cfg.withDefaults()
	return gobreaker.NewCircuitBreaker(gobreaker.Settings{
		Name:        cfg.Name,
		MaxRequests: cfg.MaxRequests,
		Interval:    cfg.Interval,
		Timeout:     cfg.OpenTimeout,
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			return counts.ConsecutiveFailures >= cfg.ConsecutiveFailures
		},
	})
}

// UnaryRetryInterceptor retries unary RPCs on transient gRPC codes; respects context cancellation.
func UnaryRetryInterceptor(cfg RetryConfig) grpc.UnaryClientInterceptor {
	cfg = cfg.withDefaults()
	retryable := codeSet(cfg.RetryableCodes)
	maxAttempts := cfg.MaxRetries + 1

	return func(
		ctx context.Context,
		method string,
		req, reply any,
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {
		var lastErr error
		for attempt := 1; attempt <= maxAttempts; attempt++ {
			if attempt > 1 {
				err := waitRetry(ctx, retryDelay(cfg, attempt-1))
				if err != nil {
					return err
				}
			}
			lastErr = invoker(ctx, method, req, reply, cc, opts...)
			if lastErr == nil {
				return nil
			}
			if attempt == maxAttempts || !shouldRetry(ctx, lastErr, retryable) {
				return lastErr
			}
		}
		return lastErr
	}
}

// UnaryCircuitBreakerInterceptor fail-fast when the dependency circuit is open.
func UnaryCircuitBreakerInterceptor(cb *gobreaker.CircuitBreaker) grpc.UnaryClientInterceptor {
	if cb == nil {
		panic("grpcutils: circuit breaker is nil")
	}
	return func(
		ctx context.Context,
		method string,
		req, reply any,
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {
		_, err := cb.Execute(func() (any, error) {
			err := invoker(ctx, method, req, reply, cc, opts...)
			if err != nil {
				return nil, err
			}
			return nil, nil
		})
		if errors.Is(err, gobreaker.ErrOpenState) || errors.Is(err, gobreaker.ErrTooManyRequests) {
			return status.Error(codes.Unavailable, "dependency circuit open")
		}
		return err
	}
}

func codeSet(codesList []codes.Code) map[codes.Code]struct{} {
	set := make(map[codes.Code]struct{}, len(codesList))
	for _, c := range codesList {
		set[c] = struct{}{}
	}
	return set
}

func shouldRetry(ctx context.Context, err error, retryable map[codes.Code]struct{}) bool {
	if err == nil {
		return false
	}
	if ctx.Err() != nil {
		return false
	}
	if errors.Is(err, context.Canceled) {
		return false
	}
	if st, ok := status.FromError(err); ok && st.Code() == codes.Canceled {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	st, ok := status.FromError(err)
	if !ok {
		return false
	}
	_, ok = retryable[st.Code()]
	return ok
}

func retryDelay(cfg RetryConfig, retryIndex int) time.Duration {
	if retryIndex < 1 {
		retryIndex = 1
	}
	delay := cfg.BaseBackoff << (retryIndex - 1)
	if delay > cfg.MaxBackoff {
		return cfg.MaxBackoff
	}
	return delay
}

func waitRetry(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
