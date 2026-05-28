package session

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
		Locale:    s.Metadata.Locale,
		Timezone:  s.Metadata.Timezone,
		Device:    s.Metadata.Device,
		Location:  s.Metadata.Location,
		UserAgent: s.Metadata.UserAgent,
		IPAddress: s.Metadata.IPAddress,
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
