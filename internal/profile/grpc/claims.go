package profilegrpc

import (
	"strings"
	"unicode"

	idclaims "sanzi.io/muid/api/proto/shared/v1/claims"
)

func claimsAreMeaningful(c *idclaims.IdentityClaims) bool {
	if c == nil {
		return false
	}
	return c.GetName() != "" ||
		c.GetGivenName() != "" ||
		c.GetFamilyName() != "" ||
		c.GetPicture() != "" ||
		c.GetLocale() != "" ||
		c.GetEmail() != ""
}

func displayNameFromClaims(c *idclaims.IdentityClaims, fallbackEmailLocal string) string {
	if c == nil {
		return ""
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
	if fallbackEmailLocal != "" {
		return fallbackEmailLocal
	}
	return ""
}

func avatarFromClaims(c *idclaims.IdentityClaims) string {
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

func sanitizeUsername(s string) string {
	var b strings.Builder
	s = strings.ToLower(strings.TrimSpace(s))
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '-' {
			b.WriteRune(r)
		}
	}
	out := b.String()
	if len(out) > 30 {
		out = out[:30]
	}
	return out
}
