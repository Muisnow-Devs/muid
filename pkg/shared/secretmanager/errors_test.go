package secretmanager

import "testing"

func TestIsNotFound(t *testing.T) {
	t.Parallel()

	if !IsNotFound(ErrSecretNotFound) {
		t.Fatal("expected secret not found")
	}
	if !IsNotFound(ErrVersionNotFound) {
		t.Fatal("expected version not found")
	}
	if IsNotFound(ErrVersionDisabled) {
		t.Fatal("did not expect disabled as not found")
	}
}
