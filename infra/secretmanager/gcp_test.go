package secretmanager

import (
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	gsm "sanzi.io/muid/pkg/shared/secretmanager"
)

func TestMapGCPError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want error
	}{
		{
			name: "secret not found",
			err:  status.Error(codes.NotFound, "Secret not found"),
			want: gsm.ErrSecretNotFound,
		},
		{
			name: "version not found",
			err:  status.Error(codes.NotFound, "Secret Version not found"),
			want: gsm.ErrVersionNotFound,
		},
		{
			name: "disabled",
			err:  status.Error(codes.FailedPrecondition, "version disabled"),
			want: gsm.ErrVersionDisabled,
		},
		{
			name: "passthrough",
			err:  status.Error(codes.PermissionDenied, "denied"),
			want: status.Error(codes.PermissionDenied, "denied"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := mapGCPError(tt.err)
			if !errors.Is(got, tt.want) && got.Error() != tt.want.Error() {
				t.Fatalf("mapGCPError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewGCPSecretManagerValidation(t *testing.T) {
	t.Parallel()

	_, err := NewGCPSecretManager(t.Context(), GCPConfig{})
	if !errors.Is(err, gsm.ErrEmptyProjectID) {
		t.Fatalf("NewGCPSecretManager err = %v", err)
	}
}
