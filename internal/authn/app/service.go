package app

import (
	"context"
	"fmt"
	"net"
	"time"

	"google.golang.org/grpc"
	pb "sanzi.io/muid/api/proto/authn/v1"
	authngrpc "sanzi.io/muid/internal/authn/grpc"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
	"sanzi.io/muid/pkg/log"
	"sanzi.io/muid/pkg/shared/tracing"
)

type AuthnGRPC struct {
	grpcServer *grpc.Server
	listener   net.Listener
}

func NewAuthnGRPC(
	config Config,
	handler pb.AuthnServiceServer,
	tracer tracing.Tracer,
) (*AuthnGRPC, error) {
	if tracer == nil {
		tracer = tracing.NewNoopTracer(tracing.NoopConfig{Debug: config.Debug})
	}

	listener, err := net.Listen("tcp", ":"+fmt.Sprint(config.Port))
	if err != nil {
		return nil, err
	}

	pvUnary, err := grpcutils.UnaryProtovalidateInterceptor()
	if err != nil {
		return nil, err
	}

	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			grpcutils.TraceUnaryInterceptor,
			grpcutils.TraceMetadataInterceptor,
			grpcutils.UnaryTracingInterceptor(tracer),
			pvUnary,
			authngrpc.AuthnRequestContextInterceptor(),
			grpcutils.RecoveryInterceptor,
			grpcutils.LoggerInterceptor,
			grpcutils.TimeoutInterceptor(time.Duration(config.RequestTimeoutSeconds)*time.Second),
		),
	)
	pb.RegisterAuthnServiceServer(grpcServer, handler)

	return &AuthnGRPC{
		grpcServer: grpcServer,
		listener:   listener,
	}, nil
}

func (s *AuthnGRPC) Start(ctx context.Context) error {
	errCh := make(chan error, 1)

	go func() {
		log.Printf("AuthnService is listening on port %d", s.listener.Addr().(*net.TCPAddr).Port)
		errCh <- s.grpcServer.Serve(s.listener)
	}()

	select {
	case <-ctx.Done():
		s.grpcServer.GracefulStop()
		return nil
	case err := <-errCh:
		return err
	}
}

func (s *AuthnGRPC) Stop() {
	s.grpcServer.GracefulStop()
}
