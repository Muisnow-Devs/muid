package app

import (
	"context"
	"fmt"
	"net"
	"time"

	"google.golang.org/grpc"

	pb "sanzi.io/muid/api/proto/profile/v1"
	profilegrpc "sanzi.io/muid/internal/profile/grpc"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
	"sanzi.io/muid/pkg/log"
	"sanzi.io/muid/pkg/shared/tracing"
)

type ProfileGRPC struct {
	grpcServer *grpc.Server
	listener   net.Listener
}

func NewProfileGRPC(
	config Config,
	handler pb.ProfileServiceServer,
	tracer tracing.Tracer,
) (*ProfileGRPC, error) {
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
			grpcutils.UnaryTracingInterceptor(tracer),
			pvUnary,
			profilegrpc.ProfileRequestContextInterceptor(),
			grpcutils.RecoveryInterceptor,
			grpcutils.LoggerInterceptor,
			grpcutils.TimeoutInterceptor(time.Duration(config.RequestTimeoutSeconds)*time.Second),
		),
	)
	pb.RegisterProfileServiceServer(grpcServer, handler)

	return &ProfileGRPC{
		grpcServer: grpcServer,
		listener:   listener,
	}, nil
}

func (s *ProfileGRPC) Start(ctx context.Context) error {
	errCh := make(chan error, 1)

	go func() {
		log.Printf("ProfileService is listening on port %d", s.listener.Addr().(*net.TCPAddr).Port)
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
