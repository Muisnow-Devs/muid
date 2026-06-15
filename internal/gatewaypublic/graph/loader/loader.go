// Package loader provides a per-request profile loader for the public gateway's
// GraphQL BFF. Listing organization members fans out to ProfileService.GetProfile
// once per member; the loader dedupes by user id (the same user can appear across
// many orgs/members) and is safe for the concurrent sibling-field resolution
// gqlgen performs. GetProfile is single-id, so the win is dedupe + concurrency
// rather than request batching.
package loader

import (
	"context"
	"sync"

	"sanzi.io/muid/internal/gatewaypublic/graph/model"
)

// FetchFunc loads a single profile by user id.
type FetchFunc func(ctx context.Context, id string) (*model.Profile, error)

type entry struct {
	once    sync.Once
	profile *model.Profile
	err     error
}

// ProfileLoader memoizes GetProfile results for the lifetime of one request.
type ProfileLoader struct {
	fetch FetchFunc

	mu    sync.Mutex
	cache map[string]*entry
}

// New builds a ProfileLoader backed by fetch.
func New(fetch FetchFunc) *ProfileLoader {
	return &ProfileLoader{fetch: fetch, cache: make(map[string]*entry)}
}

// Load returns the profile for id, fetching it at most once per request.
func (l *ProfileLoader) Load(ctx context.Context, id string) (*model.Profile, error) {
	l.mu.Lock()
	e, ok := l.cache[id]
	if !ok {
		e = &entry{}
		l.cache[id] = e
	}
	l.mu.Unlock()

	e.once.Do(func() { e.profile, e.err = l.fetch(ctx, id) })
	return e.profile, e.err
}

type ctxKey struct{}

// WithContext stores the loader on ctx for resolvers to read.
func WithContext(ctx context.Context, l *ProfileLoader) context.Context {
	return context.WithValue(ctx, ctxKey{}, l)
}

// FromContext returns the loader stored by WithContext, if any.
func FromContext(ctx context.Context) (*ProfileLoader, bool) {
	l, ok := ctx.Value(ctxKey{}).(*ProfileLoader)
	return l, ok && l != nil
}
