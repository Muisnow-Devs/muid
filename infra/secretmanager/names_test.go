package secretmanager

import (
	"testing"

	gsm "sanzi.io/muid/pkg/shared/secretmanager"
)

func TestResolveSecretName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		projectID string
		secret    string
		want      string
		wantErr   error
	}{
		{
			name:      "short id",
			projectID: "my-proj",
			secret:    "jwt-key",
			want:      "projects/my-proj/secrets/jwt-key",
		},
		{
			name:      "full resource",
			projectID: "ignored",
			secret:    "projects/other/secrets/jwt-key",
			want:      "projects/other/secrets/jwt-key",
		},
		{
			name:      "empty name",
			projectID: "p",
			secret:    "",
			wantErr:   gsm.ErrInvalidSecretRef,
		},
		{
			name:      "missing project",
			projectID: "",
			secret:    "jwt-key",
			wantErr:   gsm.ErrEmptyProjectID,
		},
		{
			name:      "invalid full name",
			projectID: "p",
			secret:    "projects/p/no-secrets-here",
			wantErr:   gsm.ErrInvalidSecretRef,
		},
		{
			name:      "slash in short id",
			projectID: "p",
			secret:    "a/b",
			wantErr:   gsm.ErrInvalidSecretRef,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := resolveSecretName(tt.projectID, tt.secret)
			if tt.wantErr != nil {
				if err != tt.wantErr {
					t.Fatalf("resolveSecretName() err = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveSecretName() err = %v", err)
			}
			if got != tt.want {
				t.Fatalf("resolveSecretName() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestVersionResourceName(t *testing.T) {
	t.Parallel()

	secret := "projects/p/secrets/s"

	got, err := versionResourceName(secret, "")
	if err != nil {
		t.Fatalf("versionResourceName: %v", err)
	}
	if got != secret+"/versions/latest" {
		t.Fatalf("got %q", got)
	}

	got, err = versionResourceName(secret, "3")
	if err != nil {
		t.Fatalf("versionResourceName: %v", err)
	}
	if got != secret+"/versions/3" {
		t.Fatalf("got %q", got)
	}

	_, err = explicitVersionResourceName(secret, "latest")
	if err != gsm.ErrInvalidSecretRef {
		t.Fatalf("explicit latest err = %v", err)
	}
}
