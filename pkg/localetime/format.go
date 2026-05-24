package localetime

import (
	"strings"
	"time"
)

// Format renders instant in the user's locale and IANA time zone.
// Layouts use only standard library time format constants.
// Empty locale falls back to English; empty or invalid timezone falls back to UTC.
func Format(instant time.Time, locale, timezone string) string {
	local := instant.In(LoadLocation(timezone))
	return local.Format(layoutForLocale(locale))
}

// LoadLocation parses an IANA time zone name, falling back to UTC.
func LoadLocation(timezone string) *time.Location {
	tz := strings.TrimSpace(timezone)
	if tz == "" {
		return time.UTC
	}

	loc, err := time.LoadLocation(tz)
	if err != nil {
		return time.UTC
	}

	return loc
}

// ValidTimezone reports whether timezone is empty or a loadable IANA name.
func ValidTimezone(timezone string) bool {
	tz := strings.TrimSpace(timezone)
	if tz == "" {
		return true
	}

	_, err := time.LoadLocation(tz)
	return err == nil
}

func layoutForLocale(locale string) string {
	locale = strings.ToLower(strings.TrimSpace(locale))
	switch {
	case strings.HasPrefix(locale, "zh"),
		strings.HasPrefix(locale, "ja"),
		strings.HasPrefix(locale, "ko"):
		return time.DateTime
	default:
		return time.RFC1123
	}
}
