package app

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	pvlib "buf.build/go/protovalidate"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/protovalidate"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/recovery"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	pb "sanzi.io/muid/api/proto/authz/v1"
	authzgrpc "sanzi.io/muid/internal/authz/grpc"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
	"sanzi.io/muid/pkg/log"
	"sanzi.io/muid/pkg/mtls"
	"sanzi.io/muid/pkg/shared/tracing"
)

// Handlers carries the four authz service implementations: User and
// OrgAdmin are registered on the public listener (gateway-fronted), Service
// and Admin on the internal listener.
type Handlers struct {
	Service  pb.AuthzServiceServer
	User     pb.AuthzUserServiceServer
	OrgAdmin pb.AuthzOrganizationAdminServiceServer
	Admin    pb.AuthzAdminServiceServer

	AdminAuthorization grpc.UnaryServerInterceptor
}

// AuthzGRPC runs the two gRPC listeners: the public surface on Config.Port
// and the internal surface on Config.InternalPort.
type AuthzGRPC struct {
	publicServer     *grpc.Server
	publicListener   net.Listener
	internalServer   *grpc.Server
	internalListener net.Listener
}

func NewAuthzGRPC(
	config Config,
	handlers Handlers,
	tracer tracing.Tracer,
) (*AuthzGRPC, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if tracer == nil {
		tracer = tracing.NewNoopTracer(tracing.NoopConfig{Debug: config.Debug})
	}

	pvValidator, err := grpcutils.ProtovalidateValidator()
	if err != nil {
		return nil, err
	}
	publicPrincipal, err := grpcutils.NewRequestPrincipalInterceptor(authzPublicPrincipalPolicies())
	if err != nil {
		return nil, err
	}
	internalPrincipal, err := grpcutils.NewRequestPrincipalInterceptor(authzInternalPrincipalPolicies())
	if err != nil {
		return nil, err
	}

	var serverTLS *tls.Config
	if config.serverTLSConfigured() {
		serverTLS, err = mtls.LoadServerTLSConfig(
			config.GRPCTLSCertPath,
			config.GRPCTLSKeyPath,
			config.GRPCMTLSClientCAPath,
		)
		if err != nil {
			return nil, fmt.Errorf("authz gRPC TLS: %w", err)
		}
	}

	publicListener, err := net.Listen("tcp", ":"+fmt.Sprint(config.Port))
	if err != nil {
		return nil, err
	}
	internalListener, err := net.Listen("tcp", ":"+fmt.Sprint(config.InternalPort))
	if err != nil {
		publicListener.Close()
		return nil, err
	}

	// The public chain additionally extracts the gateway-attached user
	// identity right after validation.
	publicOptions := []grpc.ServerOption{
		grpc.StatsHandler(otelgrpc.NewServerHandler()),
		grpc.ChainUnaryInterceptor(
			chainInterceptors(config, tracer, pvValidator,
				publicPrincipal,
				authzgrpc.PrincipalAuditInterceptor())...,
		),
	}
	if serverTLS != nil {
		publicOptions = append(publicOptions, grpc.Creds(credentials.NewTLS(serverTLS.Clone())))
	}
	publicServer := grpc.NewServer(publicOptions...)
	pb.RegisterAuthzUserServiceServer(publicServer, handlers.User)
	pb.RegisterAuthzOrganizationAdminServiceServer(publicServer, handlers.OrgAdmin)

	internalExtras := []grpc.UnaryServerInterceptor{
		internalPrincipal,
		authzgrpc.PrincipalAuditInterceptor(),
	}
	if handlers.AdminAuthorization != nil {
		internalExtras = append(internalExtras, handlers.AdminAuthorization)
	}
	internalOptions := []grpc.ServerOption{
		grpc.StatsHandler(otelgrpc.NewServerHandler()),
		grpc.ChainUnaryInterceptor(
			chainInterceptors(config, tracer, pvValidator, internalExtras...)...,
		),
	}
	if serverTLS != nil {
		internalOptions = append(internalOptions, grpc.Creds(credentials.NewTLS(serverTLS.Clone())))
	}
	internalServer := grpc.NewServer(internalOptions...)
	pb.RegisterAuthzServiceServer(internalServer, handlers.Service)
	pb.RegisterAuthzAdminServiceServer(internalServer, handlers.Admin)

	return &AuthzGRPC{
		publicServer:     publicServer,
		publicListener:   publicListener,
		internalServer:   internalServer,
		internalListener: internalListener,
	}, nil
}

func authzPublicPrincipalPolicies() map[string]grpcutils.MethodPrincipalPolicy {
	policies := make(map[string]grpcutils.MethodPrincipalPolicy)
	for _, service := range []*grpc.ServiceDesc{
		&pb.AuthzUserService_ServiceDesc,
		&pb.AuthzOrganizationAdminService_ServiceDesc,
	} {
		for _, method := range service.Methods {
			policies["/"+service.ServiceName+"/"+method.MethodName] = grpcutils.MethodPrincipalPolicy{
				Workloads: map[grpcutils.WorkloadID]grpcutils.UserMode{
					grpcutils.WorkloadGatewayPublic: grpcutils.UserRequired,
				},
			}
		}
	}
	return policies
}

func authzInternalPrincipalPolicies() map[string]grpcutils.MethodPrincipalPolicy {
	serviceWorkloads := map[grpcutils.WorkloadID]grpcutils.UserMode{
		grpcutils.WorkloadAuthn:   grpcutils.UserForbidden,
		grpcutils.WorkloadProfile: grpcutils.UserForbidden,
	}
	policies := make(map[string]grpcutils.MethodPrincipalPolicy)
	for _, method := range pb.AuthzService_ServiceDesc.Methods {
		workloads := serviceWorkloads
		if method.MethodName == "CheckPlatformPermission" {
			workloads = map[grpcutils.WorkloadID]grpcutils.UserMode{
				grpcutils.WorkloadAuthn:           grpcutils.UserForbidden,
				grpcutils.WorkloadGatewayInternal: grpcutils.UserForbidden,
			}
		}
		policies["/"+pb.AuthzService_ServiceDesc.ServiceName+"/"+method.MethodName] = grpcutils.MethodPrincipalPolicy{
			Workloads: workloads,
		}
	}
	for _, method := range pb.AuthzAdminService_ServiceDesc.Methods {
		policies["/"+pb.AuthzAdminService_ServiceDesc.ServiceName+"/"+method.MethodName] = grpcutils.MethodPrincipalPolicy{
			Workloads: map[grpcutils.WorkloadID]grpcutils.UserMode{
				grpcutils.WorkloadGatewayInternal: grpcutils.UserRequired,
			},
		}
	}
	return policies
}

// chainInterceptors builds the standard interceptor chain, splicing extra
// interceptors between validation and logging.
func chainInterceptors(
	config Config,
	tracer tracing.Tracer,
	pvValidator pvlib.Validator,
	extra ...grpc.UnaryServerInterceptor,
) []grpc.UnaryServerInterceptor {
	chain := []grpc.UnaryServerInterceptor{
		grpcutils.TraceUnaryInterceptor,
		grpcutils.TraceMetadataInterceptor,
		grpcutils.TracerContextInterceptor(tracer),
		protovalidate.UnaryServerInterceptor(pvValidator),
	}
	chain = append(chain, extra...)
	return append(chain,
		grpcutils.LoggingInterceptor(),
		grpcutils.TimeoutInterceptor(time.Duration(config.RequestTimeoutSeconds)*time.Second),
		recovery.UnaryServerInterceptor(
			recovery.WithRecoveryHandlerContext(grpcutils.PanicRecoveryHandler),
		),
	)
}

func (s *AuthzGRPC) Start(ctx context.Context) error {
	errCh := make(chan error, 2)

	go func() {
		log.Printf("AuthzService (public) is listening on port %d",
			s.publicListener.Addr().(*net.TCPAddr).Port)
		errCh <- s.publicServer.Serve(s.publicListener)
	}()
	go func() {
		log.Printf("AuthzService (internal) is listening on port %d",
			s.internalListener.Addr().(*net.TCPAddr).Port)
		errCh <- s.internalServer.Serve(s.internalListener)
	}()

	select {
	case <-ctx.Done():
		s.Stop()
		return nil
	case err := <-errCh:
		s.Stop()
		return err
	}
}

func (s *AuthzGRPC) Stop() {
	s.publicServer.GracefulStop()
	s.internalServer.GracefulStop()
}
