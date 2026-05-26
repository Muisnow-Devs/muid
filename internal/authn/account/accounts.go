package account

import "sanzi.io/muid/pkg/shared/pubsub"

// Accounts wires domain-focused account services behind a thin facade.
type Accounts struct {
	Store *Store

	Provision  Provisioning
	Email      Email
	OIDC       OIDC
	Federated  Federated
	Passkey    Passkey
	Session    Session
	LoginAlert LoginNotifier
}

// New returns account services backed by store.
// loginAlertSecureLink is AUTHN_LOGIN_ALERT_SECURE_LINK (HTTPS account security URL for login-alert mail).
func New(store *Store, pubSub pubsub.PubSub, loginAlertSecureLink string) *Accounts {
	if store == nil {
		store = &Store{}
	}
	return &Accounts{
		Store:     store,
		Provision: store,
		Email:     &emailService{store: store},
		OIDC:      &oidcService{store: store},
		Federated: &federatedService{store: store},
		Passkey:   &passkeyService{store: store, pubSub: pubSub},
		Session:   &sessionService{store: store},
		LoginAlert: &loginAlertService{
			store:      store,
			pubSub:     pubSub,
			secureLink: loginAlertSecureLink,
		},
	}
}
