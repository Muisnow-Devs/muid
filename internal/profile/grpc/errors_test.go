package profilegrpc

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"sanzi.io/muid/internal/profile/core"
	"sanzi.io/muid/internal/profile/updatemask"
)

func TestMapProfileError(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		err      error
		wantCode codes.Code
		wantMsg  string
	}{
		{
			name:     "invalid argument passthrough",
			err:      core.NewInvalidArgumentError("locale must not be empty"),
			wantCode: codes.InvalidArgument,
			wantMsg:  "locale must not be empty",
		},
		{
			name:     "empty mask",
			err:      updatemask.ErrEmptyMask,
			wantCode: codes.InvalidArgument,
			wantMsg:  "update_mask must list at least one field path",
		},
		{
			name:     "unsupported path",
			err:      core.ErrUnsupportedMaskPath,
			wantCode: codes.InvalidArgument,
			wantMsg:  "unsupported update_mask path",
		},
		{
			name:     "unknown path wrapped",
			err:      fmt.Errorf("%w: empty path", updatemask.ErrUnknownPath),
			wantCode: codes.InvalidArgument,
			wantMsg:  "unknown update_mask path",
		},
		{
			name:     "update conflict",
			err:      core.ErrUpdateConflict,
			wantCode: codes.AlreadyExists,
			wantMsg:  "conflicting update value already in use",
		},
		{
			name:     "unexpected hidden behind internal",
			err:      errors.New("pq: connection reset"),
			wantCode: codes.Internal,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertStatus(t, mapProfileError(context.Background(), "test op", tc.err),
				tc.wantCode, tc.wantMsg)
		})
	}
}

func TestMapAvatarError(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		err      error
		wantCode codes.Code
		wantMsg  string
	}{
		{
			name:     "invalid argument passthrough",
			err:      core.NewInvalidArgumentError("unreasonable object size 0"),
			wantCode: codes.InvalidArgument,
			wantMsg:  "unreasonable object size 0",
		},
		{
			name:     "not configured",
			err:      core.ErrAvatarNotConfigured,
			wantCode: codes.FailedPrecondition,
			wantMsg:  "avatar uploads are not configured (set PROFILE_R2_* variables)",
		},
		{
			name:     "profile not found",
			err:      core.ErrProfileNotFound,
			wantCode: codes.NotFound,
			wantMsg:  "profile not found",
		},
		{
			name:     "foreign object key",
			err:      core.ErrObjectKeyNotOwned,
			wantCode: codes.InvalidArgument,
			wantMsg:  "object_key does not belong to this user",
		},
		{
			name:     "session not found",
			err:      core.ErrAvatarSessionNotFound,
			wantCode: codes.NotFound,
			wantMsg:  "avatar row not found",
		},
		{
			name:     "session completed",
			err:      core.ErrAvatarSessionCompleted,
			wantCode: codes.FailedPrecondition,
			wantMsg:  "upload session already completed",
		},
		{
			name:     "object missing",
			err:      core.ErrAvatarObjectMissing,
			wantCode: codes.FailedPrecondition,
			wantMsg:  "object not found in storage",
		},
		{
			name:     "invalid image joined with detail",
			err:      errors.Join(core.ErrInvalidAvatarImage, errors.New("decode: bad header")),
			wantCode: codes.InvalidArgument,
			wantMsg:  "invalid avatar image",
		},
		{
			name:     "unexpected hidden behind internal",
			err:      errors.New("r2: timeout"),
			wantCode: codes.Internal,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertStatus(t, mapAvatarError(context.Background(), "test op", tc.err),
				tc.wantCode, tc.wantMsg)
		})
	}
}

func assertStatus(t *testing.T, err error, wantCode codes.Code, wantMsg string) {
	t.Helper()
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("not a status error: %v", err)
	}
	if st.Code() != wantCode {
		t.Fatalf("code = %v, want %v (err: %v)", st.Code(), wantCode, err)
	}
	if wantMsg != "" && st.Message() != wantMsg {
		t.Fatalf("message = %q, want %q", st.Message(), wantMsg)
	}
}
