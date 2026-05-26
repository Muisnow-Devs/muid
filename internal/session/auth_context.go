package session

import "strings"

// WithAuthContext records auth intent and optional link subject on the transition store.
func (s SessionStore) WithAuthContext(intent, linkUserID string) SessionStore {
	s.AuthIntent = strings.TrimSpace(intent)
	s.LinkUserID = strings.TrimSpace(linkUserID)
	return s
}

// WithLinkSessionWire records the wire session token validated at Start for link flows.
func (s SessionStore) WithLinkSessionWire(wire string) SessionStore {
	s.LinkSessionWire = strings.TrimSpace(wire)
	return s
}

// AuthContext returns stored intent and link user id when present.
func (s SessionStore) AuthContext() (intent, linkUserID string, ok bool) {
	intent = strings.TrimSpace(s.AuthIntent)
	linkUserID = strings.TrimSpace(s.LinkUserID)
	if intent == "" && linkUserID == "" {
		return "", "", false
	}
	return intent, linkUserID, true
}
