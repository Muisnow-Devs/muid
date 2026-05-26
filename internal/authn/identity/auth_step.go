package identity

import (
	idn "sanzi.io/muid/internal/identity"
	"sanzi.io/muid/internal/session"
)

func authenticatedStep(userID string, store session.SessionStore) idn.StepResult {
	return idn.StepResult{
		Type:            idn.StepAuthenticated,
		Authenticated:   &idn.AuthenticatedIdentity{UserID: userID},
		LoginCompletion: loginCompletionFromStore(store),
	}
}

func loginCompletionFromStore(store session.SessionStore) *idn.LoginCompletionContext {
	return &idn.LoginCompletionContext{
		Locale:    store.Locale,
		Timezone:  store.Timezone,
		Device:    store.Device,
		Location:  store.Location,
		UserAgent: store.UserAgent,
		IPAddress: store.IPAddress,
	}
}
