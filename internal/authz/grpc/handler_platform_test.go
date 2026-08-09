package authzgrpc

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "sanzi.io/muid/api/proto/authz/v1"
	"sanzi.io/muid/internal/authz/ent/enttest"
	"sanzi.io/muid/internal/authz/policy"
)

func TestCheckPlatformPermission(t *testing.T) {
	userID := uuid.New()
	handler := newPlatformHandler(t, userID)

	tests := []struct {
		name        string
		userID      string
		permission  string
		wantAllowed bool
		wantCode    codes.Code
	}{
		{
			name:        "bound user allowed",
			userID:      userID.String(),
			permission:  "platform/organization.write",
			wantAllowed: true,
		},
		{
			name:       "unbound user denied",
			userID:     uuid.NewString(),
			permission: "platform/organization.write",
		},
		{
			name:       "invalid user ID",
			userID:     "invalid",
			permission: "platform/organization.write",
			wantCode:   codes.InvalidArgument,
		},
		{
			name:       "invalid permission",
			userID:     userID.String(),
			permission: "not a permission",
			wantCode:   codes.InvalidArgument,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := &pb.CheckPlatformPermissionRequest{}
			req.SetUserId(test.userID)
			req.SetPermission(test.permission)
			resp, err := handler.CheckPlatformPermission(context.Background(), req)
			if test.wantCode != codes.OK {
				if got := status.Code(err); got != test.wantCode {
					t.Errorf("status.Code() = %v, want %v", got, test.wantCode)
				}
				return
			}
			if err != nil {
				t.Fatalf("CheckPlatformPermission: %v", err)
			}
			if resp.GetAllowed() != test.wantAllowed {
				t.Errorf("allowed = %v, want %v", resp.GetAllowed(), test.wantAllowed)
			}
		})
	}
}

func TestMapPolicyErrorHidesUnexpectedFailure(t *testing.T) {
	t.Parallel()

	err := mapPolicyError(context.Background(), "authz check platform permission", errors.New("database unavailable"))
	if got := status.Code(err); got != codes.Internal {
		t.Errorf("status.Code() = %v, want %v", got, codes.Internal)
	}
	if got := status.Convert(err).Message(); got != "internal error" {
		t.Errorf("status message = %q, want %q", got, "internal error")
	}
}

func newPlatformHandler(t *testing.T, boundUserID uuid.UUID) *GRPCHandler {
	t.Helper()
	client := enttest.Open(t, "sqlite3", "file:authzplatform?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() { client.Close() })

	config, err := policy.LoadStaticConfig("", "")
	if err != nil {
		t.Fatalf("LoadStaticConfig: %v", err)
	}
	config.PlatformBindings = map[string][]string{boundUserID.String(): {"platform_admin"}}
	manager, err := policy.NewManager(policy.ManagerConfig{DB: client, Config: config})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { manager.Close() })
	if _, _, err := manager.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	return NewGRPCHandler(HandlerConfig{Manager: manager}).(*GRPCHandler)
}
