package profilegrpc

import (
	pb "sanzi.io/muid/api/proto/profile/v1"
	"sanzi.io/muid/internal/profile/core"
)

// GRPCHandler adapts the profile domain manager to the ProfileService API:
// proto↔domain mapping plus sentinel-to-status error translation only.
type GRPCHandler struct {
	pb.UnimplementedProfileServiceServer

	mgr *core.Manager
}

func NewGRPCHandler(mgr *core.Manager) pb.ProfileServiceServer {
	return &GRPCHandler{mgr: mgr}
}
