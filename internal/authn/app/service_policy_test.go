package app

import (
	"testing"

	"google.golang.org/grpc"

	pb "sanzi.io/muid/api/proto/authn/v1"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
)

func TestAuthnPrincipalPolicies(t *testing.T) {
	t.Parallel()

	policies := authnPrincipalPolicies()
	wantCount := len(pb.AuthnService_ServiceDesc.Methods) +
		len(pb.OIDCService_ServiceDesc.Methods) +
		len(pb.OIDCClientAdminService_ServiceDesc.Methods)
	if len(policies) != wantCount {
		t.Fatalf("policy count = %d, want %d", len(policies), wantCount)
	}

	assertServicePolicy(t, policies, &pb.AuthnService_ServiceDesc, map[grpcutils.WorkloadID]grpcutils.UserMode{
		grpcutils.WorkloadGatewayPublic: grpcutils.UserForbidden,
	})
	assertServicePolicy(t, policies, &pb.OIDCService_ServiceDesc, map[grpcutils.WorkloadID]grpcutils.UserMode{
		grpcutils.WorkloadGatewayPublic: grpcutils.UserForbidden,
	})
	assertServicePolicy(t, policies, &pb.OIDCClientAdminService_ServiceDesc, map[grpcutils.WorkloadID]grpcutils.UserMode{
		grpcutils.WorkloadGatewayInternal: grpcutils.UserRequired,
	})

	assertWorkloads(t, policies[pb.AuthnService_GetPublicKeys_FullMethodName].Workloads, map[grpcutils.WorkloadID]grpcutils.UserMode{
		grpcutils.WorkloadGatewayPublic:   grpcutils.UserForbidden,
		grpcutils.WorkloadGatewayServices: grpcutils.UserForbidden,
		grpcutils.WorkloadGatewayInternal: grpcutils.UserForbidden,
	})
}

func assertServicePolicy(
	t *testing.T,
	policies map[string]grpcutils.MethodPrincipalPolicy,
	service *grpc.ServiceDesc,
	want map[grpcutils.WorkloadID]grpcutils.UserMode,
) {
	t.Helper()
	for _, method := range service.Methods {
		fullMethod := "/" + service.ServiceName + "/" + method.MethodName
		if fullMethod == pb.AuthnService_GetPublicKeys_FullMethodName {
			continue
		}
		policy, ok := policies[fullMethod]
		if !ok {
			t.Errorf("missing policy for %s", fullMethod)
			continue
		}
		assertWorkloads(t, policy.Workloads, want)
	}
}

func assertWorkloads(
	t *testing.T,
	got map[grpcutils.WorkloadID]grpcutils.UserMode,
	want map[grpcutils.WorkloadID]grpcutils.UserMode,
) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("workload count = %d, want %d", len(got), len(want))
		return
	}
	for workload, mode := range want {
		if got[workload] != mode {
			t.Errorf("workload %q mode = %v, want %v", workload, got[workload], mode)
		}
	}
}
