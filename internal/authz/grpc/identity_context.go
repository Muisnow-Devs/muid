package authzgrpc

import (
	"context"

	"github.com/google/uuid"

	grpcutils "sanzi.io/muid/pkg/grpc_utils"
)

// UserIDFromContext returns the caller identity established by the shared
// workload-principal interceptor.
func UserIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	return grpcutils.RequestUserIDFromContext(ctx)
}
