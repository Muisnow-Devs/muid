package app

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"google.golang.org/grpc"
	"sanzi.io/muid/api/proto/authn/v1"
	pb "sanzi.io/muid/api/proto/authn/v1"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
)

type AuthnService struct {
	grpcServer *grpc.Server
	listener   net.Listener
}

func NewAuthnService(config Config, handler authn.AuthnServiceServer) (*AuthnService, error) {
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
	pb.RegisterAuthnServiceServer(grpcServer, handler)

	return &AuthnService{
		grpcServer: grpcServer,
		listener:   listener,
	}, nil
}

func (s *AuthnService) Start(ctx context.Context) error {
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

func (s *AuthnService) Stop() {
	s.grpcServer.GracefulStop()
}
