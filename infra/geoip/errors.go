package geoip

import "errors"

var (
	// ErrInvalidIP is returned when the supplied string is not a valid IP.
	ErrInvalidIP = errors.New("geoip: invalid ip address")
	// ErrUnavailable is returned when no database is currently loaded.
	ErrUnavailable = errors.New("geoip: database unavailable")
)
