package app

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/protovalidate"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/recovery"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"

	pb "sanzi.io/muid/api/proto/authz/v1"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
	"sanzi.io/muid/pkg/log"
	"sanzi.io/muid/pkg/shared/tracing"
)

type AuthzGRPC struct {
	grpcServer *grpc.Server
	listener   net.Listener
}

func NewAuthzGRPC(
	config Config,
	handler pb.AuthzServiceServer,
	tracer tracing.Tracer,
) (*AuthzGRPC, error) {
	if tracer == nil {
		tracer = tracing.NewNoopTracer(tracing.NoopConfig{Debug: config.Debug})
	}

	listener, err := net.Listen("tcp", ":"+fmt.Sprint(config.Port))
	if err != nil {
		return nil, err
	}

	pvValidator, err := grpcutils.ProtovalidateValidator()
	if err != nil {
		return nil, err
	}

	grpcServer := grpc.NewServer(
		grpc.StatsHandler(otelgrpc.NewServerHandler()),
		grpc.ChainUnaryInterceptor(
			grpcutils.TraceUnaryInterceptor,
			grpcutils.TraceMetadataInterceptor,
			grpcutils.TracerContextInterceptor(tracer),
			protovalidate.UnaryServerInterceptor(pvValidator),
			grpcutils.LoggingInterceptor(),
			grpcutils.TimeoutInterceptor(time.Duration(config.RequestTimeoutSeconds)*time.Second),
			recovery.UnaryServerInterceptor(
				recovery.WithRecoveryHandlerContext(grpcutils.PanicRecoveryHandler),
			),
		),
	)
	pb.RegisterAuthzServiceServer(grpcServer, handler)

	return &AuthzGRPC{
		grpcServer: grpcServer,
		listener:   listener,
	}, nil
}

func (s *AuthzGRPC) Start(ctx context.Context) error {
	errCh := make(chan error, 1)

	go func() {
		log.Printf("AuthzService is listening on port %d", s.listener.Addr().(*net.TCPAddr).Port)
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

func (s *AuthzGRPC) Stop() {
	s.grpcServer.GracefulStop()
}
