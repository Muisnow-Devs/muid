package identity

import (
	idn "sanzi.io/muid/internal/identity"
	"sanzi.io/muid/internal/session"
)

func authenticatedStep(userID string, store session.SessionStore) idn.StepResult {
	return idn.StepResult{
		Type:          idn.StepAuthenticated,
		Authenticated: &idn.AuthenticatedIdentity{UserID: userID},
		LoginCompletion: &idn.LoginCompletionContext{
			Locale:   store.Locale,
			Timezone: store.Timezone,
		},
	}
}
