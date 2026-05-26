package session

import "sanzi.io/muid/pkg/clientmeta"

// ApplyClientMeta copies locale, timezone, and login-alert device context onto a transition store.
func ApplyClientMeta(store *SessionStore, m clientmeta.ClientMeta) {
	if store == nil {
		return
	}
	store.Locale = m.Locale
	store.Timezone = m.Timezone
	store.Device = m.Device
	store.Location = m.Location
	store.UserAgent = m.UserAgent
	store.IPAddress = m.IPAddress
}

// MailClientContext holds client metadata on a transition for outbound login-alert mail.
type MailClientContext struct {
	Locale    string
	Timezone  string
	Device    string
	Location  string
	UserAgent string
	IPAddress string
}

// MailClientContext returns persisted client metadata for mail events.
func (s SessionStore) MailClientContext() MailClientContext {
	return MailClientContext{
		Locale:    s.Locale,
		Timezone:  s.Timezone,
		Device:    s.Device,
		Location:  s.Location,
		UserAgent: s.UserAgent,
		IPAddress: s.IPAddress,
	}
}

// MergeMailClientContext prefers primary fields and fills empty ones from fallback.
func MergeMailClientContext(primary, fallback MailClientContext) MailClientContext {
	out := primary
	if out.Locale == "" {
		out.Locale = fallback.Locale
	}
	if out.Timezone == "" {
		out.Timezone = fallback.Timezone
	}
	if out.Device == "" {
		out.Device = fallback.Device
	}
	if out.Location == "" {
		out.Location = fallback.Location
	}
	if out.UserAgent == "" {
		out.UserAgent = fallback.UserAgent
	}
	if out.IPAddress == "" {
		out.IPAddress = fallback.IPAddress
	}
	return out
}
