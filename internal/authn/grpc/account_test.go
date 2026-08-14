package authngrpc

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "sanzi.io/muid/api/proto/authn/v1"
	"sanzi.io/muid/internal/authn/account"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
)

type accountReaderFunc func(context.Context, uuid.UUID) (account.Snapshot, error)

func (f accountReaderFunc) GetMyAccount(ctx context.Context, userID uuid.UUID) (account.Snapshot, error) {
	return f(ctx, userID)
}

func TestGetMyAccountMapsSnapshot(t *testing.T) {
	t.Parallel()

	statuses := map[account.Status]pb.AccountStatus{
		account.StatusActive:          pb.AccountStatus_ACCOUNT_STATUS_ACTIVE,
		account.StatusDisabled:        pb.AccountStatus_ACCOUNT_STATUS_DISABLED,
		account.StatusPendingDeletion: pb.AccountStatus_ACCOUNT_STATUS_PENDING_DELETION,
	}
	for domainStatus, protoStatus := range statuses {
		domainStatus, protoStatus := domainStatus, protoStatus
		t.Run(string(domainStatus), func(t *testing.T) {
			t.Parallel()
			userID := uuid.New()
			createdAt := time.Now().UTC().Truncate(time.Second)
			linkedAt := createdAt.Add(time.Minute)
			h := NewGRPCHandler(HandlerDependencies{AccountReader: accountReaderFunc(
				func(_ context.Context, got uuid.UUID) (account.Snapshot, error) {
					if got != userID {
						t.Fatalf("user ID = %s, want %s", got, userID)
					}
					return account.Snapshot{
						Status:       domainStatus,
						PrimaryEmail: "user@example.com",
						CreatedAt:    createdAt,
						LinkedIdentities: []account.LinkedIdentity{{
							Provider: "google",
							LinkedAt: linkedAt,
						}},
					}, nil
				},
			)})

			ctx := grpcutils.WithRequestUserID(context.Background(), userID)
			resp, err := h.GetMyAccount(ctx, &pb.GetMyAccountRequest{})
			if err != nil {
				t.Fatalf("GetMyAccount: %v", err)
			}
			got := resp.GetAccount()
			if got.GetUserId() != userID.String() || got.GetPrimaryEmail() != "user@example.com" ||
				!got.GetPrimaryEmailVerified() || got.GetAccountStatus() != protoStatus ||
				!got.GetCreatedAt().AsTime().Equal(createdAt) {
				t.Fatalf("account = %v", got)
			}
			if len(got.GetLinkedIdentities()) != 1 ||
				got.GetLinkedIdentities()[0].GetProvider() != "google" ||
				!got.GetLinkedIdentities()[0].GetLinkedAt().AsTime().Equal(linkedAt) {
				t.Fatalf("linked identities = %v", got.GetLinkedIdentities())
			}
		})
	}
}

func TestGetMyAccountFailures(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	ctx := grpcutils.WithRequestUserID(context.Background(), userID)
	tests := []struct {
		name   string
		reader account.Reader
		ctx    context.Context
		want   codes.Code
	}{
		{name: "unavailable", ctx: ctx, want: codes.Unavailable},
		{name: "missing principal", reader: accountReaderFunc(func(context.Context, uuid.UUID) (account.Snapshot, error) {
			return account.Snapshot{}, nil
		}), ctx: context.Background(), want: codes.Unauthenticated},
		{name: "not found", reader: accountReaderFunc(func(context.Context, uuid.UUID) (account.Snapshot, error) {
			return account.Snapshot{}, account.ErrNotFound
		}), ctx: ctx, want: codes.NotFound},
		{name: "database", reader: accountReaderFunc(func(context.Context, uuid.UUID) (account.Snapshot, error) {
			return account.Snapshot{}, errors.New("database failed")
		}), ctx: ctx, want: codes.Internal},
		{name: "canceled", reader: accountReaderFunc(func(context.Context, uuid.UUID) (account.Snapshot, error) {
			return account.Snapshot{}, fmt.Errorf("query account: %w", context.Canceled)
		}), ctx: ctx, want: codes.Canceled},
		{name: "deadline exceeded", reader: accountReaderFunc(func(context.Context, uuid.UUID) (account.Snapshot, error) {
			return account.Snapshot{}, fmt.Errorf("query account: %w", context.DeadlineExceeded)
		}), ctx: ctx, want: codes.DeadlineExceeded},
		{name: "invalid status", reader: accountReaderFunc(func(context.Context, uuid.UUID) (account.Snapshot, error) {
			return account.Snapshot{Status: "unknown", CreatedAt: time.Now()}, nil
		}), ctx: ctx, want: codes.Internal},
		{name: "invalid time", reader: accountReaderFunc(func(context.Context, uuid.UUID) (account.Snapshot, error) {
			return account.Snapshot{Status: account.StatusActive, CreatedAt: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)}, nil
		}), ctx: ctx, want: codes.Internal},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := NewGRPCHandler(HandlerDependencies{AccountReader: tc.reader})
			_, err := h.GetMyAccount(tc.ctx, &pb.GetMyAccountRequest{})
			if status.Code(err) != tc.want {
				t.Fatalf("code = %v, want %v (err %v)", status.Code(err), tc.want, err)
			}
			if tc.want == codes.Internal && status.Convert(err).Message() != "internal error" {
				t.Fatalf("message = %q, want fixed internal error", status.Convert(err).Message())
			}
		})
	}
}
