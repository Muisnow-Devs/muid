package account

import "strings"

// MailDeliveryPrefs carries locale and timezone from the client auth request for outbound mail.
type MailDeliveryPrefs struct {
	Locale   string
	Timezone string
}

// NormalizedLocale returns the BCP-47 locale, defaulting to "en" when empty.
func (p MailDeliveryPrefs) NormalizedLocale() string {
	locale := strings.TrimSpace(p.Locale)
	if locale == "" {
		return "en"
	}
	return locale
}

// NormalizedTimezone returns a trimmed IANA time zone; empty means UTC in the mailer.
func (p MailDeliveryPrefs) NormalizedTimezone() string {
	return strings.TrimSpace(p.Timezone)
}
