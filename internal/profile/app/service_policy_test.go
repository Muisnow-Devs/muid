package app

import (
	"testing"

	pb "sanzi.io/muid/api/proto/profile/v1"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
)

func TestProfilePrincipalPolicies(t *testing.T) {
	t.Parallel()

	policies := profilePrincipalPolicies()
	assertProfileWorkloadMode(t, policies, pb.ProfileService_CreateProfile_FullMethodName,
		grpcutils.WorkloadAuthn, grpcutils.UserForbidden)
	assertProfileWorkloadMode(t, policies, pb.ProfileService_GetProfile_FullMethodName,
		grpcutils.WorkloadAuthn, grpcutils.UserForbidden)
	assertProfileWorkloadMode(t, policies, pb.ProfileService_GetProfile_FullMethodName,
		grpcutils.WorkloadGatewayPublic, grpcutils.UserOptional)
	assertProfileWorkloadMode(t, policies, pb.ProfileService_GetProfile_FullMethodName,
		grpcutils.WorkloadGatewayServices, grpcutils.UserRequired)
	assertProfileWorkloadMode(t, policies, pb.ProfileService_UpdateProfile_FullMethodName,
		grpcutils.WorkloadGatewayPublic, grpcutils.UserRequired)
	assertProfileWorkloadMode(t, policies,
		pb.OrganizationProfileService_CreateOrganizationProfile_FullMethodName,
		grpcutils.WorkloadAuthz, grpcutils.UserForbidden)
	assertProfileWorkloadMode(t, policies,
		pb.OrganizationProfileService_UpdateOrganizationProfile_FullMethodName,
		grpcutils.WorkloadGatewayPublic, grpcutils.UserRequired)
}

func assertProfileWorkloadMode(
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
