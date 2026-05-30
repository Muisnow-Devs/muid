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

// IdentityProvider pairs an IdentityMethod with its per-method IdentityStore.
// The store is kept here so that VerifiedIdentity no longer needs to carry it.
type IdentityProvider struct {
	Method method.IdentityMethod
	Store  identitystore.IdentityStore
}

// IdentityManager manages all singleton instances of IdentityMethod. Each method
// is wired with its own IdentityStore so that no method needs a direct database
// dependency.
type IdentityManager struct {
	transitionStore session.AuthTransitionStore
	providers       map[string]IdentityProvider
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

	providers := make(map[string]IdentityProvider)
	providers["email"] = IdentityProvider{
		Method: method.NewEmailOTPMethod(
			emailStore,
			otpStore,
			transitionStore,
			pubSub,
			cooldownSeconds,
		),
		Store: emailStore,
	}
	providers["passkey"] = IdentityProvider{
		Method: method.NewPasskeyMethod(passkeyStore, transitionStore, wa),
		Store:  passkeyStore,
	}

	for _, cfg := range oidcConfigs {
		m, err := method.NewOIDCMethod(ctx, cfg, oidcStore, transitionStore)
		if err != nil {
			return nil, fmt.Errorf("failed to create OIDC provider %s: %w", cfg.Name, err)
		}
		providers[cfg.Name] = IdentityProvider{
			Method: m,
			Store:  oidcStore,
		}
	}

	return &IdentityManager{
		transitionStore: transitionStore,
		providers:       providers,
	}, nil
}

// GetProvider retrieves the IdentityProvider (method + store) registered under
// the given name. Callers that need only the method or only the store use the
// relevant field of the returned struct.
func (m *IdentityManager) GetProvider(name string) (IdentityProvider, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	p, ok := m.providers[name]
	if !ok || p.Method == nil {
		return IdentityProvider{}, fmt.Errorf("identity provider %q not found", name)
	}
	return p, nil
}

// Close cleans up registered methods.
func (m *IdentityManager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, p := range m.providers {
		if closer, ok := p.Method.(io.Closer); ok {
			closer.Close()
		}
	}
}
