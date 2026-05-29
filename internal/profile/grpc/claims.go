package profilegrpc

import (
	"strings"

	idclaims "sanzi.io/muid/api/proto/shared/v1/claims"
)

func displayNameFromIdentity(c *idclaims.IdentityInformation) string {
	if c == nil {
		return randomDisplayName()
	}

	if n := strings.TrimSpace(c.GetName()); n != "" {
		return n
	}

	g := strings.TrimSpace(c.GetGivenName())
	f := strings.TrimSpace(c.GetFamilyName())

	combo := strings.TrimSpace(g + " " + f)
	if combo != "" {
		return combo
	}

	return randomDisplayName()
}

func avatarFromIdentity(c *idclaims.IdentityInformation) string {
	if c == nil {
		return ""
	}

	return strings.TrimSpace(c.GetPicture())
}

func emailLocalPart(email string) string {
	at := strings.LastIndex(email, "@")
	if at <= 0 {
		return ""
	}
	return strings.TrimSpace(email[:at])
}
