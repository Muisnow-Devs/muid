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

	pb "sanzi.io/muid/api/proto/authn/v1"
	authngrpc "sanzi.io/muid/internal/authn/grpc"
	"sanzi.io/muid/internal/identity/issuer"
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
	oidcHandler pb.OIDCServiceServer,
	oidcAdminHandler pb.OIDCClientAdminServiceServer,
	iss issuer.SessionIssuer,
	tracer tracing.Tracer,
) (*AuthnGRPC, error) {
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
			grpcutils.SessionTokenInterceptor(),
			protovalidate.UnaryServerInterceptor(pvValidator),
			authngrpc.AuthnRequestContextInterceptor(),
			authngrpc.AuthnSessionPrincipalInterceptor(iss),
			grpcutils.LoggingInterceptor(),
			grpcutils.TimeoutInterceptor(time.Duration(config.RequestTimeoutSeconds)*time.Second),
			recovery.UnaryServerInterceptor(
				recovery.WithRecoveryHandlerContext(grpcutils.PanicRecoveryHandler),
			),
		),
	)
	pb.RegisterAuthnServiceServer(grpcServer, handler)
	pb.RegisterOIDCServiceServer(grpcServer, oidcHandler)
	pb.RegisterOIDCClientAdminServiceServer(grpcServer, oidcAdminHandler)

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
