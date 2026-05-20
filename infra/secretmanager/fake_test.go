package secretmanager

import (
	"context"
	"errors"
	"testing"

	gsm "sanzi.io/muid/pkg/shared/secretmanager"
)

func TestFakeSecretManagerLifecycle(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	sm := NewFakeSecretManager("test-proj")
	fake, ok := sm.(*FakeSecretManager)
	if !ok {
		t.Fatal("expected *FakeSecretManager")
	}

	err := fake.SeedVersion("signing-key", "1", []byte("v1"))
	if err != nil {
		t.Fatalf("SeedVersion: %v", err)
	}

	value, version, err := sm.GetSecret(ctx, gsm.SecretRef{Name: "signing-key"})
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if string(value) != "v1" || version != "1" {
		t.Fatalf("GetSecret = (%q, %q)", value, version)
	}

	version, err = sm.RotateSecret(ctx, gsm.SecretRef{Name: "signing-key"}, []byte("v2"))
	if err != nil {
		t.Fatalf("RotateSecret: %v", err)
	}
	if version != "2" {
		t.Fatalf("RotateSecret version = %q", version)
	}

	value, version, err = sm.GetSecret(ctx, gsm.SecretRef{Name: "signing-key", Version: "latest"})
	if err != nil {
		t.Fatalf("GetSecret latest: %v", err)
	}
	if string(value) != "v2" || version != "2" {
		t.Fatalf("GetSecret latest = (%q, %q)", value, version)
	}

	err = sm.RevokeSecret(ctx, gsm.SecretRef{Name: "signing-key", Version: "1"})
	if err != nil {
		t.Fatalf("RevokeSecret: %v", err)
	}

	_, _, err = sm.GetSecret(ctx, gsm.SecretRef{Name: "signing-key", Version: "1"})
	if !errors.Is(err, gsm.ErrVersionDisabled) {
		t.Fatalf("GetSecret revoked err = %v", err)
	}

	value, version, err = sm.GetSecret(ctx, gsm.SecretRef{Name: "signing-key", Version: "latest"})
	if err != nil {
		t.Fatalf("GetSecret after revoke: %v", err)
	}
	if string(value) != "v2" || version != "2" {
		t.Fatalf("GetSecret after revoke = (%q, %q)", value, version)
	}

	enabled, err := fake.EnabledVersions("signing-key")
	if err != nil {
		t.Fatalf("EnabledVersions: %v", err)
	}
	if len(enabled) != 1 || enabled[0] != "2" {
		t.Fatalf("EnabledVersions = %v", enabled)
	}
}

func TestFakeSecretManagerErrors(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	sm := NewFakeSecretManager("p")

	_, _, err := sm.GetSecret(ctx, gsm.SecretRef{Name: "missing"})
	if !errors.Is(err, gsm.ErrSecretNotFound) {
		t.Fatalf("GetSecret missing err = %v", err)
	}

	_, err = sm.RotateSecret(ctx, gsm.SecretRef{Name: "k"}, nil)
	if !errors.Is(err, gsm.ErrInvalidSecretRef) {
		t.Fatalf("RotateSecret empty err = %v", err)
	}

	err = sm.RevokeSecret(ctx, gsm.SecretRef{Name: "k", Version: "latest"})
	if !errors.Is(err, gsm.ErrInvalidSecretRef) {
		t.Fatalf("RevokeSecret latest err = %v", err)
	}
}
