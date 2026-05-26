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
