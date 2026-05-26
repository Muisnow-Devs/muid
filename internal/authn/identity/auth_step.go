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
	m := store.MailClientContext()
	return &idn.LoginCompletionContext{
		Locale:    m.Locale,
		Timezone:  m.Timezone,
		Device:    m.Device,
		Location:  m.Location,
		UserAgent: m.UserAgent,
		IPAddress: m.IPAddress,
	}
}
