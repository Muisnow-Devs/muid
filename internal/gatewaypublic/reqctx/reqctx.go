// Package reqctx carries per-request facts (client IP, resolved geo) extracted
// by the public gateway's protector middleware across to the request handlers
// and GraphQL resolvers. It lives in its own package so both the app middleware
// (writer) and the graph resolvers (reader) can use it without an import cycle.
package reqctx

import (
	"context"
	"net/http"

	"google.golang.org/grpc/metadata"

	"sanzi.io/muid/pkg/gateway/httpmeta"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
)

// Facts are the request attributes the gateway forwards to backends.
type Facts struct {
	ClientIP   string
	GeoCountry string
}

type ctxKey struct{}

// WithFacts returns a child context carrying f.
func WithFacts(ctx context.Context, f Facts) context.Context {
	return context.WithValue(ctx, ctxKey{}, f)
}

// FactsFromContext returns the stored facts when present.
func FactsFromContext(ctx context.Context) (Facts, bool) {
	f, ok := ctx.Value(ctxKey{}).(Facts)
	return f, ok
}

// OutgoingMetadata attaches the stored client IP + geo to ctx as outgoing gRPC
// metadata for a downstream backend call. Trace id is forwarded separately by
// the dial interceptor.
func OutgoingMetadata(ctx context.Context) context.Context {
	f, ok := FactsFromContext(ctx)
	if !ok {
		return ctx
	}
	return httpmeta.WithOutgoing(ctx, httpmeta.Fields{
		ClientIP:   f.ClientIP,
		GeoCountry: f.GeoCountry,
	})
}

// OutgoingAuthenticated is OutgoingMetadata plus the gateway-verified caller id
// under the unified identity key httpmeta.UserIDKey ("x-user-id"). authz and
// profile both read this single key (pkg/shared/authn.AuthenticatedUserIDMetadataKey
// is unified to the same value), so one ctx works for either data-plane backend.
func OutgoingAuthenticated(ctx context.Context, userID string) context.Context {
	ctx = OutgoingMetadata(ctx)
	if userID == "" {
		return ctx
	}
	return metadata.AppendToOutgoingContext(ctx, httpmeta.UserIDKey, userID)
}

// OutgoingMetadataWithSession is OutgoingMetadata plus the opaque session token
// presented to authn as the "Session <token>" authorization metadata header
// (matching grpcutils.SessionTokenInterceptor). An empty token is omitted, so
// it is safe to call for unauthenticated flows (e.g. login).
func OutgoingMetadataWithSession(ctx context.Context, sessionToken string) context.Context {
	ctx = OutgoingMetadata(ctx)
	if sessionToken == "" {
		return ctx
	}
	return metadata.AppendToOutgoingContext(ctx, grpcutils.AuthorizationMetadataKey, "Session "+sessionToken)
}

type httpKey struct{}

// HTTPTxn holds the live HTTP request/response so resolvers can read request
// cookies and write Set-Cookie headers (the session token never travels in the
// GraphQL body).
type HTTPTxn struct {
	W http.ResponseWriter
	R *http.Request
}

// WithHTTP returns a child context carrying the request/response writer.
func WithHTTP(ctx context.Context, w http.ResponseWriter, r *http.Request) context.Context {
	return context.WithValue(ctx, httpKey{}, &HTTPTxn{W: w, R: r})
}

// HTTPFromContext returns the HTTP round-trip stored by WithHTTP, when present.
func HTTPFromContext(ctx context.Context) (*HTTPTxn, bool) {
	t, ok := ctx.Value(httpKey{}).(*HTTPTxn)
	return t, ok && t != nil
}
