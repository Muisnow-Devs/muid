package authngrpc

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "sanzi.io/muid/api/proto/authn/v1"
	"sanzi.io/muid/internal/authn/account"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
	"sanzi.io/muid/pkg/log"
)

// GetMyAccount returns the account state for the authenticated request user.
func (h *GRPCHandler) GetMyAccount(
	ctx context.Context,
	_ *pb.GetMyAccountRequest,
) (*pb.GetMyAccountResponse, error) {
	if h.accountReader == nil {
		return nil, status.Error(codes.Unavailable, "account unavailable")
	}
	userID, ok := grpcutils.RequestUserIDFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "user identity required")
	}

	snapshot, err := h.accountReader.GetMyAccount(ctx, userID)
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return nil, status.FromContextError(err).Err()
	}
	if errors.Is(err, account.ErrNotFound) {
		return nil, status.Error(codes.NotFound, "account not found")
	}
	if err != nil {
		log.LogUnexpected(ctx, "get my account", err.Error(), log.UserID(userID))
		return nil, grpcutils.GRPCInternalError()
	}

	outAccount, err := accountProto(userID.String(), snapshot)
	if err != nil {
		log.LogUnexpected(ctx, "encode my account", err.Error(), log.UserID(userID))
		return nil, grpcutils.GRPCInternalError()
	}
	out := &pb.GetMyAccountResponse{}
	out.SetAccount(outAccount)
	return out, nil
}

func accountProto(userID string, snapshot account.Snapshot) (*pb.Account, error) {
	statusValue, err := accountStatusProto(snapshot.Status)
	if err != nil {
		return nil, err
	}
	createdAt := timestamppb.New(snapshot.CreatedAt)
	if err = createdAt.CheckValid(); err != nil {
		return nil, fmt.Errorf("created at: %w", err)
	}

	linked := make([]*pb.LinkedIdentitySummary, 0, len(snapshot.LinkedIdentities))
	for _, identity := range snapshot.LinkedIdentities {
		linkedAt := timestamppb.New(identity.LinkedAt)
		if err = linkedAt.CheckValid(); err != nil {
			return nil, fmt.Errorf("linked at: %w", err)
		}
		summary := &pb.LinkedIdentitySummary{}
		summary.SetProvider(identity.Provider)
		summary.SetLinkedAt(linkedAt)
		linked = append(linked, summary)
	}

	out := &pb.Account{}
	out.SetUserId(userID)
	out.SetPrimaryEmail(snapshot.PrimaryEmail)
	out.SetPrimaryEmailVerified(true)
	out.SetAccountStatus(statusValue)
	out.SetCreatedAt(createdAt)
	out.SetLinkedIdentities(linked)
	return out, nil
}

func accountStatusProto(statusValue account.Status) (pb.AccountStatus, error) {
	switch statusValue {
	case account.StatusActive:
		return pb.AccountStatus_ACCOUNT_STATUS_ACTIVE, nil
	case account.StatusDisabled:
		return pb.AccountStatus_ACCOUNT_STATUS_DISABLED, nil
	case account.StatusPendingDeletion:
		return pb.AccountStatus_ACCOUNT_STATUS_PENDING_DELETION, nil
	default:
		return pb.AccountStatus_ACCOUNT_STATUS_UNSPECIFIED, account.ErrInvalidState
	}
}
