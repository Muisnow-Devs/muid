package identity

import (
	"sync"

	"sanzi.io/muid/internal/session"
)

type IdentityManager struct {
	transitionStore session.AuthTransitionStore

	providers map[string]IdentityProvider
	mu        sync.Mutex
}

func NewIdentityManager(transitionStore session.AuthTransitionStore, providers ...IdentityProvider) *IdentityManager {
	providersMap := make(map[string]IdentityProvider)
	for _, provider := range providers {
		providersMap[provider.Name()] = provider
	}

	return &IdentityManager{transitionStore: transitionStore, providers: providersMap}
}

func (m *IdentityManager) AddProvider(provider IdentityProvider) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.providers[provider.Name()]; exists {
		return ErrProviderExists
	}

	m.providers[provider.Name()] = provider
	return nil
}

func (m *IdentityManager) GetProvider(name string) (IdentityProvider, error) {
	provider, exists := m.providers[name]
	if !exists {
		return nil, ErrProviderNotFound
	}

	return provider, nil
}

func (m *IdentityManager) Close() {
	for name := range m.providers {
		delete(m.providers, name)
	}
}
