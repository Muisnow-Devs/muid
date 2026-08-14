package jwtauth

import "context"

type claimsCtxKey struct{}
type rawBearerCtxKey struct{}

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

func withRawBearer(ctx context.Context, raw string) context.Context {
	return context.WithValue(ctx, rawBearerCtxKey{}, raw)
}

// RawBearerFromContext returns the exact bearer value retained only after
// successful verification. Callers must treat it as a secret and never log or
// serialize it.
func RawBearerFromContext(ctx context.Context) (string, bool) {
	raw, ok := ctx.Value(rawBearerCtxKey{}).(string)
	return raw, ok
}
