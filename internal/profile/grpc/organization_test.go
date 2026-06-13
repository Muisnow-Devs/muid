package profilegrpc

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	pb "sanzi.io/muid/api/proto/profile/v1"
	"sanzi.io/muid/internal/profile/core"
	sharedauthn "sanzi.io/muid/pkg/shared/authn"
)

type fakeOrgEnforcer struct {
	allowed bool
	gotPerm string
}

func (f *fakeOrgEnforcer) Enforce(_ context.Context, _, _ uuid.UUID, perm string) (bool, error) {
	f.gotPerm = perm
	return f.allowed, nil
}

// TestUpdateOrganizationProfileAuthorization exercises the handler's
// authorization branches; the actual persistence is covered by core tests.
func TestUpdateOrganizationProfileAuthorization(t *testing.T) {
	t.Parallel()

	// The manager is never reached in these branches (denial/unavailable/
	// missing principal short-circuit before the DB call).
	mgr := core.NewManager(core.ManagerConfig{})
	orgID := uuid.New()
	caller := uuid.New()

	authedCtx := func() context.Context {
		return sharedauthn.WithAuthenticatedUserID(context.Background(), caller)
	}
	newReq := func() *pb.UpdateOrganizationProfileRequest {
		req := &pb.UpdateOrganizationProfileRequest{}
		req.SetOrganizationId(orgID.String())
		req.SetUpdateMask(&fieldmaskpb.FieldMask{Paths: []string{"description"}})
		req.SetDescription("x")
		return req
	}

	t.Run("denied when caller lacks org.manage", func(t *testing.T) {
		enf := &fakeOrgEnforcer{allowed: false}
		h := NewOrganizationGRPCHandler(mgr, enf)
		_, err := h.UpdateOrganizationProfile(authedCtx(), newReq())
		assertStatus(t, err, codes.PermissionDenied, "")
		if enf.gotPerm != orgManagePermission {
			t.Errorf("enforced permission = %q, want %q", enf.gotPerm, orgManagePermission)
		}
	})

	t.Run("unconfigured enforcer is unavailable", func(t *testing.T) {
		h := NewOrganizationGRPCHandler(mgr, nil)
		_, err := h.UpdateOrganizationProfile(authedCtx(), newReq())
		assertStatus(t, err, codes.Unavailable, "")
	})
}
