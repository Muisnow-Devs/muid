package signature

import (
	"context"
	"time"

	"sanzi.io/muid/api/proto/authn/v1/certification"
	gsm "sanzi.io/muid/pkg/shared/secretmanager"
)

// SecretManager is the shared backend used by SignatureManager.
type SecretManager = gsm.SecretManager

// SecretRef identifies a managed signing secret.
type SecretRef = gsm.SecretRef

// SignatureManager signs and validates OIDC provider payloads without exposing private keys.
type SignatureManager interface {
	Start(ctx context.Context) error
	Sign(ctx context.Context, data []byte) (Signature, error)
	Verify(ctx context.Context, data []byte, sig Signature) (bool, error)
	PublicKeys(ctx context.Context) ([]*certification.PublicKey, error)
	RotateSecret(ctx context.Context) (KeyMetadata, error)
	RevokeSecret(ctx context.Context, keyID string) error
	Close() error
}

// Signature is an asymmetric signature and the public metadata needed to validate it.
type Signature struct {
	KeyID     string
	Alg       string
	Signature []byte
}

// KeyMetadata is returned after rotating to a new signing key.
type KeyMetadata struct {
	KeyID   string
	Version string
	Alg     string
}

// ManagerConfig configures a SecretManager-backed SignatureManager.
type ManagerConfig struct {
	SecretName string
	KeyBits    int
	// PreviousGenerations controls how many older versions are kept available for validation.
	// Values below one are treated as one.
	PreviousGenerations int
	// RotationPeriod controls background private key rotation.
	// Zero uses the manager default; negative disables the background job.
	// In read-only mode the same period drives cache refresh instead of rotation.
	RotationPeriod time.Duration
	// ReadOnly makes the manager a follower: it signs and validates with keys
	// loaded from the SecretManager but never rotates or revokes them. Start
	// runs a periodic cache refresh so rotations done elsewhere are picked up.
	ReadOnly bool
}
