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
	"google.golang.org/grpc/credentials"

	pb "sanzi.io/muid/api/proto/profile/v1"
	profilegrpc "sanzi.io/muid/internal/profile/grpc"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
	"sanzi.io/muid/pkg/log"
	"sanzi.io/muid/pkg/mtls"
	"sanzi.io/muid/pkg/shared/tracing"
)

type ProfileGRPC struct {
	grpcServer *grpc.Server
	listener   net.Listener
}

func NewProfileGRPC(
	config Config,
	handler pb.ProfileServiceServer,
	orgHandler pb.OrganizationProfileServiceServer,
	tracer tracing.Tracer,
) (*ProfileGRPC, error) {
	if err := mtls.ValidatePathGroup(
		true,
		config.GRPCTLSCertPath,
		config.GRPCTLSKeyPath,
		config.GRPCMTLSClientCAPath,
	); err != nil {
		return nil, fmt.Errorf("profile inbound gRPC TLS: %w", err)
	}
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
	principal, err := grpcutils.NewRequestPrincipalInterceptor(profilePrincipalPolicies())
	if err != nil {
		return nil, err
	}

	serverTLS, err := mtls.LoadServerTLSConfig(
		config.GRPCTLSCertPath,
		config.GRPCTLSKeyPath,
		config.GRPCMTLSClientCAPath,
	)
	if err != nil {
		return nil, fmt.Errorf("profile gRPC TLS: %w", err)
	}

	serverOptions := []grpc.ServerOption{
		grpc.StatsHandler(otelgrpc.NewServerHandler()),
		grpc.ChainUnaryInterceptor(
			grpcutils.TraceUnaryInterceptor,
			grpcutils.TraceMetadataInterceptor,
			grpcutils.TracerContextInterceptor(tracer),
			protovalidate.UnaryServerInterceptor(pvValidator),
			principal,
			profilegrpc.ProfileRequestContextInterceptor(),
			grpcutils.LoggingInterceptor(),
			grpcutils.TimeoutInterceptor(time.Duration(config.RequestTimeoutSeconds)*time.Second),
			recovery.UnaryServerInterceptor(
				recovery.WithRecoveryHandlerContext(grpcutils.PanicRecoveryHandler),
			),
		),
	}
	serverOptions = append(serverOptions, grpc.Creds(credentials.NewTLS(serverTLS)))
	grpcServer := grpc.NewServer(serverOptions...)
	pb.RegisterProfileServiceServer(grpcServer, handler)
	pb.RegisterOrganizationProfileServiceServer(grpcServer, orgHandler)

	return &ProfileGRPC{
		grpcServer: grpcServer,
		listener:   listener,
	}, nil
}

func profilePrincipalPolicies() map[string]grpcutils.MethodPrincipalPolicy {
	return map[string]grpcutils.MethodPrincipalPolicy{
		pb.ProfileService_CreateProfile_FullMethodName: {
			Workloads: map[grpcutils.WorkloadID]grpcutils.UserMode{
				grpcutils.WorkloadAuthn: grpcutils.UserForbidden,
			},
		},
		pb.ProfileService_GetProfile_FullMethodName: {
			Workloads: map[grpcutils.WorkloadID]grpcutils.UserMode{
				grpcutils.WorkloadAuthn:           grpcutils.UserForbidden,
				grpcutils.WorkloadGatewayPublic:   grpcutils.UserOptional,
				grpcutils.WorkloadGatewayServices: grpcutils.UserRequired,
			},
		},
		pb.ProfileService_UpdateProfile_FullMethodName: {
			Workloads: map[grpcutils.WorkloadID]grpcutils.UserMode{
				grpcutils.WorkloadGatewayPublic: grpcutils.UserRequired,
			},
		},
		pb.ProfileService_StartAvatarUpload_FullMethodName: {
			Workloads: map[grpcutils.WorkloadID]grpcutils.UserMode{
				grpcutils.WorkloadGatewayPublic: grpcutils.UserRequired,
			},
		},
		pb.ProfileService_CompleteAvatarUpload_FullMethodName: {
			Workloads: map[grpcutils.WorkloadID]grpcutils.UserMode{
				grpcutils.WorkloadGatewayPublic: grpcutils.UserRequired,
			},
		},
		pb.OrganizationProfileService_CreateOrganizationProfile_FullMethodName: {
			Workloads: map[grpcutils.WorkloadID]grpcutils.UserMode{
				grpcutils.WorkloadAuthz: grpcutils.UserForbidden,
			},
		},
		pb.OrganizationProfileService_GetOrganizationProfile_FullMethodName: {
			Workloads: map[grpcutils.WorkloadID]grpcutils.UserMode{
				grpcutils.WorkloadGatewayPublic: grpcutils.UserRequired,
			},
		},
		pb.OrganizationProfileService_UpdateOrganizationProfile_FullMethodName: {
			Workloads: map[grpcutils.WorkloadID]grpcutils.UserMode{
				grpcutils.WorkloadGatewayPublic: grpcutils.UserRequired,
			},
		},
	}
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
