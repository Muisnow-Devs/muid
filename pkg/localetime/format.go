package localetime

import (
	"strings"
	"time"
)

// Format renders instant in the user's locale and IANA time zone.
// Layouts include a numeric UTC offset so mail recipients can see the timezone.
// Empty locale falls back to English; empty or invalid timezone falls back to UTC.
func Format(instant time.Time, locale, timezone string) string {
	local := instant.In(LoadLocation(timezone))
	return local.Format(time.RFC1123Z)
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
