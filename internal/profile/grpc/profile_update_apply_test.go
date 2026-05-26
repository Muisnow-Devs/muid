package profilegrpc

import (
	"strings"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	pb "sanzi.io/muid/api/proto/profile/v1"
	claimspb "sanzi.io/muid/api/proto/shared/v1/claims"
)

func TestSortedPatchableProfileMaskPaths_acceptsBio(t *testing.T) {
	t.Parallel()

	mask := &fieldmaskpb.FieldMask{Paths: []string{"identity.bio"}}
	got, err := sortedPatchableProfileMaskPaths(mask)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "identity.bio" {
		t.Fatalf("got %v", got)
	}
}

func TestPatchIdentityBio(t *testing.T) {
	t.Parallel()

	t.Run("requires identity", func(t *testing.T) {
		t.Parallel()
		req := &pb.UpdateProfileRequest{}
		err := patchIdentityBio(t.Context(), uuid.Nil, nil, req)
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("rejects overlong bio", func(t *testing.T) {
		t.Parallel()
		idn := &claimspb.IdentityInformation{}
		idn.SetBio(strings.Repeat("x", 1025))
		req := &pb.UpdateProfileRequest{}
		req.SetIdentity(idn)
		err := patchIdentityBio(t.Context(), uuid.Nil, nil, req)
		if err == nil {
			t.Fatal("expected error")
		}
	})
}
