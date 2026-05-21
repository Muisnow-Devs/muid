package account

// Accounts wires domain-focused account services behind a thin facade.
type Accounts struct {
	Store *Store

	Provision Provisioning
	Email     Email
	OIDC      OIDC
	Passkey   Passkey
	Session   Session
}

// New returns account services backed by store.
func New(store *Store) *Accounts {
	if store == nil {
		store = &Store{}
	}
	return &Accounts{
		Store:     store,
		Provision: store,
		Email:     &emailService{store: store},
		OIDC:      &oidcService{store: store},
		Passkey:   &passkeyService{store: store},
		Session:   &sessionService{store: store},
	}
}
