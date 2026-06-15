package jwtauth

import "context"

type claimsCtxKey struct{}

// WithClaims returns a child context carrying the verified caller claims. It is
// the single place gateways stash identity resolved by the auth interceptor /
// middleware, so readers (BFF handlers, downstream middleware) share one key.
func WithClaims(ctx context.Context, claims Claims) context.Context {
	return context.WithValue(ctx, claimsCtxKey{}, claims)
}

// ClaimsFromContext returns the verified claims when the caller is authenticated.
func ClaimsFromContext(ctx context.Context) (Claims, bool) {
	c, ok := ctx.Value(claimsCtxKey{}).(Claims)
	return c, ok
}
