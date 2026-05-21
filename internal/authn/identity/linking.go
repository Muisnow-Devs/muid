package identity

import (
	"context"
	"errors"
	"strings"

	"sanzi.io/muid/internal/authn/account"
	idn "sanzi.io/muid/internal/identity"
	"sanzi.io/muid/internal/session"
)

func resolveLinkSession(
	ctx context.Context,
	accounts *account.Accounts,
	intent idn.AuthIntent,
	linkToken string,
) (account.ResolvedSession, error) {
	if intent != idn.IntentLinkAccount {
		return account.ResolvedSession{}, nil
	}

	linkToken = strings.TrimSpace(linkToken)
	if linkToken == "" {
		return account.ResolvedSession{}, idn.ErrLinkUnauthorized
	}

	res, err := accounts.Session.ResolveSessionToken(ctx, linkToken)
	if errors.Is(err, session.ErrSessionNotFound) || errors.Is(err, session.ErrSessionExpired) {
		return account.ResolvedSession{}, idn.ErrLinkUnauthorized
	}

	if err != nil {
		return account.ResolvedSession{}, err
	}

	return res, nil
}
