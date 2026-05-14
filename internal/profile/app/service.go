package app

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"google.golang.org/grpc"

	pb "sanzi.io/muid/api/proto/profile/v1"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
)

type ProfileGRPC struct {
	grpcServer *grpc.Server
	listener   net.Listener
}

func NewProfileGRPC(config Config, handler pb.ProfileServiceServer) (*ProfileGRPC, error) {
	listener, err := net.Listen("tcp", ":"+fmt.Sprint(config.Port))
	if err != nil {
		return nil, err
	}

	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			grpcutils.TraceUnaryInterceptor,
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

func (s *ProfileGRPC) Stop() {
	s.grpcServer.GracefulStop()
}
