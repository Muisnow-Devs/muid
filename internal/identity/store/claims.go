package store

import "sanzi.io/muid/internal/authn/ent/userpasskey"

// DeviceType re-exports the passkey device type so callers only need to
// import the store package, not the ent sub-package.
type DeviceType = userpasskey.DeviceType

const (
	DeviceTypeSingleDevice = userpasskey.DeviceTypeSingleDevice
	DeviceTypeMultiDevice  = userpasskey.DeviceTypeMultiDevice
)

// IdentityClaims is the sealed interface for method-specific identity data.
// Implementations carry the information needed by each IdentityStore to
// persist the identity sub-table atomically alongside UserIdentity.
type IdentityClaims interface {
	IdentityClaimsKind() string
}

// EmailIdentityClaims carries the data required to link an email identity.
type EmailIdentityClaims struct {
	Email         string
	EmailVerified bool
}

func (EmailIdentityClaims) IdentityClaimsKind() string { return "email" }

// OIDCIdentityClaims carries the data required to link a federated OIDC identity.
type OIDCIdentityClaims struct {
	Provider      string
	Subject       string
	Email         string
	EmailVerified bool
	DisplayName   string
	AvatarURL     string
}

func (OIDCIdentityClaims) IdentityClaimsKind() string { return "oidc" }

// PasskeyIdentityClaims carries the data required to link a passkey identity.
type PasskeyIdentityClaims struct {
	CredentialID   []byte
	PublicKey      []byte
	RPID           string
	DeviceType     userpasskey.DeviceType
	BackupEligible bool
	BackupState    bool
	// Transports is the set of authenticator transports (usb, nfc, ble, internal, …).
	Transports []string
	// DisplayName is the human-readable name shown in passkey management UIs.
	DisplayName string
}

func (PasskeyIdentityClaims) IdentityClaimsKind() string { return "passkey" }
