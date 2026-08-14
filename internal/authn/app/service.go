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

	pb "sanzi.io/muid/api/proto/authn/v1"
	authngrpc "sanzi.io/muid/internal/authn/grpc"
	"sanzi.io/muid/internal/identity/issuer"
	"sanzi.io/muid/internal/oidctoken"
	"sanzi.io/muid/pkg/authzclient"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
	"sanzi.io/muid/pkg/log"
	"sanzi.io/muid/pkg/mtls"
	"sanzi.io/muid/pkg/shared/tracing"
)

type AuthnGRPC struct {
	grpcServer *grpc.Server
	listener   net.Listener
}

type focusedAuthnServer interface {
	pb.AuthenticationFlowServiceServer
	pb.SessionServiceServer
	pb.LinkedIdentityServiceServer
	pb.SigningKeyServiceServer
	pb.AccountServiceServer
}

func NewAuthnGRPC(
	config Config,
	handler focusedAuthnServer,
	oidcHandler pb.OIDCServiceServer,
	oidcAdminHandler pb.OIDCClientAdminServiceServer,
	iss issuer.SessionIssuer,
	accountVerifier *oidctoken.Verifier,
	platformAuthz *authzclient.PlatformChecker,
	tracer tracing.Tracer,
) (*AuthnGRPC, error) {
	if err := mtls.ValidatePathGroup(
		true,
		config.GRPCTLSCertPath,
		config.GRPCTLSKeyPath,
		config.GRPCMTLSClientCAPath,
	); err != nil {
		return nil, fmt.Errorf("authn inbound gRPC TLS: %w", err)
	}
	if tracer == nil {
		tracer = tracing.NewNoopTracer(tracing.NoopConfig{Debug: config.Debug})
	}

	pvValidator, err := grpcutils.ProtovalidateValidator()
	if err != nil {
		return nil, err
	}
	principal, err := grpcutils.NewRequestPrincipalInterceptor(authnPrincipalPolicies())
	if err != nil {
		return nil, err
	}

	serverTLS, err := mtls.LoadServerTLSConfig(
		config.GRPCTLSCertPath,
		config.GRPCTLSKeyPath,
		config.GRPCMTLSClientCAPath,
	)
	if err != nil {
		return nil, fmt.Errorf("authn gRPC TLS: %w", err)
	}

	listener, err := net.Listen("tcp", ":"+fmt.Sprint(config.Port))
	if err != nil {
		return nil, err
	}

	serverOptions := []grpc.ServerOption{
		grpc.StatsHandler(otelgrpc.NewServerHandler()),
		grpc.ChainUnaryInterceptor(
			grpcutils.TraceUnaryInterceptor,
			grpcutils.TraceMetadataInterceptor,
			grpcutils.TracerContextInterceptor(tracer),
			protovalidate.UnaryServerInterceptor(pvValidator),
			principal,
			grpcutils.TimeoutInterceptor(time.Duration(config.RequestTimeoutSeconds)*time.Second),
			authngrpc.AccountDelegationInterceptor(accountVerifier),
			grpcutils.SessionTokenInterceptor(),
			authngrpc.AuthnRequestContextInterceptor(),
			authngrpc.AuthnSessionPrincipalInterceptor(iss),
			authngrpc.OIDCAdminPlatformAuthorizationInterceptor(platformAuthz),
			grpcutils.LoggingInterceptor(),
			recovery.UnaryServerInterceptor(
				recovery.WithRecoveryHandlerContext(grpcutils.PanicRecoveryHandler),
			),
		),
	}
	serverOptions = append(serverOptions, grpc.Creds(credentials.NewTLS(serverTLS)))
	grpcServer := grpc.NewServer(serverOptions...)
	pb.RegisterAuthenticationFlowServiceServer(grpcServer, handler)
	pb.RegisterSessionServiceServer(grpcServer, handler)
	pb.RegisterLinkedIdentityServiceServer(grpcServer, handler)
	pb.RegisterSigningKeyServiceServer(grpcServer, handler)
	pb.RegisterAccountServiceServer(grpcServer, handler)
	pb.RegisterOIDCServiceServer(grpcServer, oidcHandler)
	pb.RegisterOIDCClientAdminServiceServer(grpcServer, oidcAdminHandler)

	return &AuthnGRPC{
		grpcServer: grpcServer,
		listener:   listener,
	}, nil
}

func authnPrincipalPolicies() map[string]grpcutils.MethodPrincipalPolicy {
	policies := make(map[string]grpcutils.MethodPrincipalPolicy)
	publicServices := []*grpc.ServiceDesc{
		&pb.AuthenticationFlowService_ServiceDesc,
		&pb.SessionService_ServiceDesc,
		&pb.LinkedIdentityService_ServiceDesc,
	}
	for _, service := range publicServices {
		for _, method := range service.Methods {
			policies["/"+service.ServiceName+"/"+method.MethodName] = grpcutils.MethodPrincipalPolicy{
				Workloads: map[grpcutils.WorkloadID]grpcutils.UserMode{
					grpcutils.WorkloadGatewayPublic: grpcutils.UserForbidden,
				},
			}
		}
	}
	for _, method := range pb.SigningKeyService_ServiceDesc.Methods {
		policies["/"+pb.SigningKeyService_ServiceDesc.ServiceName+"/"+method.MethodName] = grpcutils.MethodPrincipalPolicy{
			Workloads: map[grpcutils.WorkloadID]grpcutils.UserMode{
				grpcutils.WorkloadGatewayPublic:   grpcutils.UserForbidden,
				grpcutils.WorkloadGatewayServices: grpcutils.UserForbidden,
				grpcutils.WorkloadGatewayInternal: grpcutils.UserForbidden,
			},
		}
	}
	for _, method := range pb.AccountService_ServiceDesc.Methods {
		policies["/"+pb.AccountService_ServiceDesc.ServiceName+"/"+method.MethodName] = grpcutils.MethodPrincipalPolicy{
			Workloads: map[grpcutils.WorkloadID]grpcutils.UserMode{
				grpcutils.WorkloadGatewayServices: grpcutils.UserRequired,
			},
		}
	}
	for _, method := range pb.OIDCService_ServiceDesc.Methods {
		policies["/"+pb.OIDCService_ServiceDesc.ServiceName+"/"+method.MethodName] = grpcutils.MethodPrincipalPolicy{
			Workloads: map[grpcutils.WorkloadID]grpcutils.UserMode{
				grpcutils.WorkloadGatewayPublic: grpcutils.UserForbidden,
			},
		}
	}
	for _, method := range pb.OIDCClientAdminService_ServiceDesc.Methods {
		policies["/"+pb.OIDCClientAdminService_ServiceDesc.ServiceName+"/"+method.MethodName] = grpcutils.MethodPrincipalPolicy{
			Workloads: map[grpcutils.WorkloadID]grpcutils.UserMode{
				grpcutils.WorkloadGatewayInternal: grpcutils.UserRequired,
			},
		}
	}
	return policies
}

func (s *AuthnGRPC) Start(ctx context.Context) error {
	errCh := make(chan error, 1)

	go func() {
		log.Printf("authn gRPC is listening on port %d", s.listener.Addr().(*net.TCPAddr).Port)
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
