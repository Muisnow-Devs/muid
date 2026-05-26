package account

import "sanzi.io/muid/pkg/shared/pubsub"

// Wire builds account domain services from a shared store. Each return value is a
// focused interface for injection at call sites (flow, identity providers, gRPC).
func Wire(
	store *Store,
	pubSub pubsub.PubSub,
	loginAlertSecureLink string,
) (
	Provisioning,
	Email,
	OIDC,
	Federated,
	Passkey,
	Session,
	LoginNotifier,
) {
	if store == nil {
		store = &Store{}
	}
	return store,
		NewEmailService(store),
		NewOIDCService(store),
		NewFederatedService(store),
		NewPasskeyService(store, pubSub),
		NewSessionService(store),
		NewLoginAlertService(store, pubSub, loginAlertSecureLink)
}

func NewEmailService(store *Store) Email {
	return &emailService{store: store}
}

func NewOIDCService(store *Store) OIDC {
	return &oidcService{store: store}
}

func NewFederatedService(store *Store) Federated {
	return &federatedService{store: store}
}

func NewPasskeyService(store *Store, pubSub pubsub.PubSub) Passkey {
	return &passkeyService{store: store, pubSub: pubSub}
}

func NewSessionService(store *Store) Session {
	return &sessionService{store: store}
}

func NewLoginAlertService(
	store *Store,
	pubSub pubsub.PubSub,
	secureLink string,
) LoginNotifier {
	return &loginAlertService{
		store:      store,
		pubSub:     pubSub,
		secureLink: secureLink,
	}
}
