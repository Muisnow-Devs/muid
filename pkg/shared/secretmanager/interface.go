// Package secretmanager defines the shared secret-store contract for swappable backends.
package secretmanager

import "context"

// SecretRef identifies a secret and optionally a version.
//
// Name is either a secret id (e.g. "jwt-signing-key") or a full resource name
// "projects/{project}/secrets/{secret_id}" when the backend supports it.
//
// Version is used by [SecretManager.GetSecret] and [SecretManager.RevokeSecret].
// Empty or "latest" resolves to the latest enabled version for Get.
// Revoke requires an explicit numeric version id (not "latest").
type SecretRef struct {
	Name    string
	Version string
}

// SecretManager reads secret payloads and manages secret versions.
type SecretManager interface {
	// GetSecret returns the payload and resolved version id for ref.
	GetSecret(ctx context.Context, ref SecretRef) (value []byte, version string, err error)
	// RotateSecret appends a new secret version with payload and returns its version id.
	RotateSecret(ctx context.Context, ref SecretRef, payload []byte) (version string, err error)
	// RevokeSecret disables the version in ref so it can no longer be accessed.
	RevokeSecret(ctx context.Context, ref SecretRef) error
	Close() error
}
