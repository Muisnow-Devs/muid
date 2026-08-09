package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/protovalidate"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/recovery"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	gatewaypb "sanzi.io/muid/api/proto/gateway/v1"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
	"sanzi.io/muid/pkg/log"
	"sanzi.io/muid/pkg/shared/tracing"
)

// ServicesGRPC runs the services gateway's gRPC listener.
type ServicesGRPC struct {
	server          grpcServer
	listener        net.Listener
	mtls            bool
	shutdownTimeout time.Duration
}

type grpcServer interface {
	Serve(net.Listener) error
	GracefulStop()
	Stop()
}

const defaultGRPCShutdownTimeout = 15 * time.Second

// NewServicesGRPC builds the gRPC server with the standard interceptor chain,
// the gateway's JWT-auth + rate-limit interceptors, and mTLS credentials when
// configured.
func NewServicesGRPC(
	deps *InfraDependencies,
	handler gatewaypb.ServicesGatewayServiceServer,
	tracer tracing.Tracer,
) (*ServicesGRPC, error) {
	cfg := deps.GlobalConfig
	if tracer == nil {
		tracer = tracing.NewNoopTracer(tracing.NoopConfig{Debug: cfg.Debug})
	}

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.Port))
	if err != nil {
		return nil, err
	}

	pvValidator, err := grpcutils.ProtovalidateValidator()
	if err != nil {
		listener.Close()
		return nil, err
	}

	limiter := newRateLimiter(deps)

	opts := []grpc.ServerOption{
		grpc.StatsHandler(otelgrpc.NewServerHandler()),
		grpc.ChainUnaryInterceptor(
			grpcutils.TraceUnaryInterceptor,
			grpcutils.TraceMetadataInterceptor,
			grpcutils.TracerContextInterceptor(tracer),
			protovalidate.UnaryServerInterceptor(pvValidator),
			authInterceptor(deps.Verifier),
			rateLimitInterceptor(limiter, cfg.TrustForwardHeader),
			grpcutils.LoggingInterceptor(),
			grpcutils.TimeoutInterceptor(time.Duration(cfg.RequestTimeoutSeconds)*time.Second),
			recovery.UnaryServerInterceptor(
				recovery.WithRecoveryHandlerContext(grpcutils.PanicRecoveryHandler),
			),
		),
	}
	if deps.TLSConfig != nil {
		opts = append(opts, grpc.Creds(credentials.NewTLS(deps.TLSConfig)))
	}

	server := grpc.NewServer(opts...)
	gatewaypb.RegisterServicesGatewayServiceServer(server, handler)

	return &ServicesGRPC{
		server:          server,
		listener:        listener,
		mtls:            deps.TLSConfig != nil,
		shutdownTimeout: grpcShutdownTimeout(cfg.RequestTimeoutSeconds),
	}, nil
}

func grpcShutdownTimeout(requestTimeoutSeconds int) time.Duration {
	timeout := time.Duration(requestTimeoutSeconds)*time.Second + 5*time.Second
	if timeout < defaultGRPCShutdownTimeout {
		return defaultGRPCShutdownTimeout
	}
	return timeout
}

// Run serves until ctx is cancelled or serving fails. Cancellation performs a
// bounded graceful drain and forcibly stops remaining RPCs when the budget is
// exhausted.
func (s *ServicesGRPC) Run(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		log.Printf("gateway-services (gRPC) is listening on %s (mtls=%t)", s.listener.Addr().String(), s.mtls)
		errCh <- s.server.Serve(s.listener)
	}()

	select {
	case <-ctx.Done():
		s.shutdown()
		return normalizeGRPCServeError(<-errCh)
	case err := <-errCh:
		serveErr := normalizeGRPCServeError(err)
		if serveErr == nil {
			return nil
		}
		s.shutdown()
		return serveErr
	}
}

func (s *ServicesGRPC) shutdown() {
	done := make(chan struct{})
	go func() {
		s.server.GracefulStop()
		close(done)
	}()

	timer := time.NewTimer(s.shutdownTimeout)
	defer timer.Stop()
	select {
	case <-done:
		return
	case <-timer.C:
		s.server.Stop()
		<-done
	}
}

func normalizeGRPCServeError(err error) error {
	if errors.Is(err, grpc.ErrServerStopped) {
		return nil
	}
	return err
}
