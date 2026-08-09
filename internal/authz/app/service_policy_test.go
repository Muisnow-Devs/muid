package app

import (
	"testing"

	pb "sanzi.io/muid/api/proto/authz/v1"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
)

func TestAuthzPrincipalPolicies(t *testing.T) {
	t.Parallel()

	public := authzPublicPrincipalPolicies()
	assertWorkloadMode(
		t,
		public,
		pb.AuthzUserService_CheckMyPermission_FullMethodName,
		grpcutils.WorkloadGatewayPublic,
		grpcutils.UserRequired,
	)
	assertWorkloadMode(
		t,
		public,
		pb.AuthzOrganizationAdminService_CreateRole_FullMethodName,
		grpcutils.WorkloadGatewayPublic,
		grpcutils.UserRequired,
	)

	internal := authzInternalPrincipalPolicies()
	assertWorkloadMode(
		t,
		internal,
		pb.AuthzService_CheckOrganizationPermission_FullMethodName,
		grpcutils.WorkloadAuthn,
		grpcutils.UserForbidden,
	)
	assertWorkloadMode(
		t,
		internal,
		pb.AuthzService_CheckOrganizationPermission_FullMethodName,
		grpcutils.WorkloadProfile,
		grpcutils.UserForbidden,
	)
	assertWorkloadMode(
		t,
		internal,
		pb.AuthzService_CheckPlatformPermission_FullMethodName,
		grpcutils.WorkloadGatewayInternal,
		grpcutils.UserForbidden,
	)
	assertWorkloadMode(
		t,
		internal,
		pb.AuthzAdminService_ReloadPolicyConfig_FullMethodName,
		grpcutils.WorkloadGatewayInternal,
		grpcutils.UserRequired,
	)
}

func assertWorkloadMode(
	t *testing.T,
	policies map[string]grpcutils.MethodPrincipalPolicy,
	method string,
	workload grpcutils.WorkloadID,
	want grpcutils.UserMode,
) {
	t.Helper()
	policy, ok := policies[method]
	if !ok {
		t.Fatalf("missing policy for %s", method)
	}
	got, ok := policy.Workloads[workload]
	if !ok {
		t.Fatalf("method %s does not allow workload %s", method, workload)
	}
	if got != want {
		t.Fatalf("method %s workload %s mode = %v, want %v", method, workload, got, want)
	}
}
