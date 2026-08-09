// Package geoip resolves client IPs to geographic facts using a MaxMind mmdb
// database. The database file is typically mounted into the container and
// refreshed out-of-band; the resolver watches the file and hot-reloads when a
// newer version appears. Only exported interfaces and config live here;
// implementations are in sibling files and stable errors in errors.go.
package geoip

import (
	"context"
	"io"
)

// GeoInfo is the subset of MaxMind data the gateways consume.
type GeoInfo struct {
	IP          string
	CountryCode string // ISO 3166-1 alpha-2
	CountryName string
	City        string
	Resolved    bool
}

// Resolver maps an IP string to a GeoInfo. Implementations must be safe for
// concurrent use.
type Resolver interface {
	io.Closer
	// Resolve returns geo facts for ip. A well-formed IP with no database
	// entry yields a GeoInfo with Resolved=false and a nil error.
	Resolve(ip string) (GeoInfo, error)
}

// Watcher is a Resolver whose backing database can be hot-reloaded by watching
// the source file for changes.
type Watcher interface {
	Resolver
	// StartWatch begins polling the database file for updates until ctx is
	// cancelled. It returns immediately, is idempotent, and Close cancels and
	// joins the watcher before releasing the active database.
	StartWatch(ctx context.Context)
}
