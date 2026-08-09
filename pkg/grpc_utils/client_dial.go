package grpcutils

import (
	"crypto/tls"
	"fmt"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"sanzi.io/muid/pkg/log"
)

// DialInsecureClient dials target with trace forwarding, optional circuit breaker (outer) and retry (inner).
// extraOpts are appended after the standard transport and interceptor options.
func DialInsecureClient(
	target string,
	resilience ClientResilienceConfig,
	extraOpts ...grpc.DialOption,
) (*grpc.ClientConn, error) {
	return dialClient(target, resilience, insecure.NewCredentials(), extraOpts...)
}

// DialTLSClient dials target with a cloned TLS config, trace forwarding, and
// optional circuit breaker and retry interceptors. TLS verification is left to
// the standard gRPC transport credentials, including normal DNS/IP SAN checks.
func DialTLSClient(
	target string,
	tlsConfig *tls.Config,
	resilience ClientResilienceConfig,
	extraOpts ...grpc.DialOption,
) (*grpc.ClientConn, error) {
	if tlsConfig == nil {
		return nil, fmt.Errorf("grpcutils: nil TLS config")
	}
	return dialClient(target, resilience, credentials.NewTLS(tlsConfig.Clone()), extraOpts...)
}

func dialClient(
	target string,
	resilience ClientResilienceConfig,
	transportCredentials credentials.TransportCredentials,
	extraOpts ...grpc.DialOption,
) (*grpc.ClientConn, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, fmt.Errorf("grpcutils: empty dial target")
	}

	interceptors := []grpc.UnaryClientInterceptor{
		log.UnaryClientInterceptor(),
	}

	cbCfg := resilience.CircuitBreaker.withDefaults()
	if cbCfg.Enabled {
		interceptors = append(
			interceptors,
			UnaryCircuitBreakerInterceptor(NewCircuitBreaker(cbCfg)),
		)
	}

	retryCfg := resilience.Retry.withDefaults()
	if retryCfg.MaxRetries > 0 {
		interceptors = append(interceptors, UnaryRetryInterceptor(retryCfg))
	}

	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(transportCredentials),
		grpc.WithChainUnaryInterceptor(interceptors...),
	}
	opts = append(opts, extraOpts...)

	conn, err := grpc.NewClient(target, opts...)
	if err != nil {
		return nil, fmt.Errorf("grpcutils: dial %q: %w", target, err)
	}
	return conn, nil
}
