package grpcutils

import (
	"fmt"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"sanzi.io/muid/pkg/traceid"
)

// DialInsecureClient dials target with trace forwarding, optional circuit breaker (outer) and retry (inner).
// extraOpts are appended after the standard transport and interceptor options.
func DialInsecureClient(target string, resilience ClientResilienceConfig, extraOpts ...grpc.DialOption) (*grpc.ClientConn, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, fmt.Errorf("grpcutils: empty dial target")
	}

	interceptors := []grpc.UnaryClientInterceptor{
		traceid.UnaryClientInterceptor(),
	}

	cbCfg := resilience.CircuitBreaker.withDefaults()
	if cbCfg.Enabled {
		interceptors = append(interceptors, UnaryCircuitBreakerInterceptor(NewCircuitBreaker(cbCfg)))
	}

	retryCfg := resilience.Retry.withDefaults()
	if retryCfg.MaxRetries > 0 {
		interceptors = append(interceptors, UnaryRetryInterceptor(retryCfg))
	}

	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithChainUnaryInterceptor(interceptors...),
	}
	opts = append(opts, extraOpts...)

	conn, err := grpc.NewClient(target, opts...)
	if err != nil {
		return nil, fmt.Errorf("grpcutils: dial %q: %w", target, err)
	}
	return conn, nil
}
