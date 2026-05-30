package identity

import (
	"context"
	"fmt"
	"io"
	"sync"

	"github.com/go-webauthn/webauthn/webauthn"
	authnconfig "sanzi.io/muid/internal/authn/config"
	authnent "sanzi.io/muid/internal/authn/ent"
	"sanzi.io/muid/internal/identity/method"
	identitystore "sanzi.io/muid/internal/identity/store"
	"sanzi.io/muid/internal/otp"
	"sanzi.io/muid/internal/session"
	"sanzi.io/muid/pkg/shared/pubsub"
)

// IdentityManager manages all singleton instances of IdentityMethod. Each method
// is wired with its own IdentityStore so that no method needs a direct database
// dependency.
type IdentityManager struct {
	transitionStore session.AuthTransitionStore
	providers       map[string]method.IdentityMethod
	mu              sync.RWMutex
}

// NewIdentityManager creates a new IdentityManager, creates per-method stores
// from the shared Ent client, and pre-instantiates all methods.
func NewIdentityManager(
	ctx context.Context,
	db *authnent.Client,
	otpStore otp.OTPStore,
	transitionStore session.AuthTransitionStore,
	pubSub pubsub.PubSub,
	wa *webauthn.WebAuthn,
	cooldownSeconds int,
	oidcConfigs []authnconfig.OIDCProviderConfig,
) (*IdentityManager, error) {
	emailStore := identitystore.NewEntEmailIdentityStore(db)
	oidcStore := identitystore.NewEntOIDCIdentityStore(db)
	passkeyStore := identitystore.NewEntPasskeyIdentityStore(db)

	identityProvider := make(map[string]method.IdentityMethod)
	identityProvider["email"] = method.NewEmailOTPMethod(
		emailStore,
		otpStore,
		transitionStore,
		pubSub,
		cooldownSeconds,
	)
	identityProvider["passkey"] = method.NewPasskeyMethod(passkeyStore, transitionStore, wa)

	for _, cfg := range oidcConfigs {
		m, err := method.NewOIDCMethod(ctx, cfg, oidcStore, transitionStore)
		if err != nil {
			return nil, fmt.Errorf("failed to create OIDC provider %s: %w", cfg.Name, err)
		}
		identityProvider[cfg.Name] = m
	}

	return &IdentityManager{
		transitionStore: transitionStore,
		providers:       identityProvider,
	}, nil
}

// GetMethod retrieves a registered IdentityMethod by name.
func (m *IdentityManager) GetMethod(name string) (method.IdentityMethod, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	provider, ok := m.providers[name]
	if !ok || provider == nil {
		return nil, fmt.Errorf("identity method %q not found", name)
	}
	return provider, nil
}

// Close cleans up registered methods.
func (m *IdentityManager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, provider := range m.providers {
		if closer, ok := provider.(io.Closer); ok {
			closer.Close()
		}
	}
}
