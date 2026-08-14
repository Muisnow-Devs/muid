// Package jwtauth verifies muid session access tokens locally at the gateway
// edge using the authn JWKS, without calling back to authn. It mirrors the
// header/claim checks in internal/oidctoken/sessionaccess.go (typ
// "muid-session+jwt", token_use "session") but verifies the RS256 signature
// directly against RSA public keys fetched from a KeySource.
package jwtauth

import (
	"context"
	"crypto/rsa"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/sync/singleflight"

	"sanzi.io/muid/pkg/log"
)

const (
	// sessionAccessTokenTyp must match internal/oidctoken's session JWS typ.
	sessionAccessTokenTyp = "muid-session+jwt"
	// sessionTokenUse must match internal/oidctoken's token_use discriminator.
	sessionTokenUse = "session"
)

var (
	// ErrInvalidToken is returned for malformed, mis-typed, or wrongly-signed tokens.
	ErrInvalidToken = errors.New("jwtauth: invalid token")
	// ErrExpiredToken is returned for expired tokens.
	ErrExpiredToken = errors.New("jwtauth: expired token")
	// ErrUnknownKey is returned when no JWKS key matches the token's kid.
	ErrUnknownKey = errors.New("jwtauth: unknown signing key")
	// ErrNoUsableKeys is returned by a KeySource when a successful fetch yields no
	// usable signing keys, so the verifier serves its last-good cache instead of
	// caching an empty keyset.
	ErrNoUsableKeys = errors.New("jwtauth: no usable signing keys")
)

// KeySource supplies the current set of RSA verification keys keyed by kid.
type KeySource interface {
	Keys(ctx context.Context) (map[string]*rsa.PublicKey, error)
}

// Claims are the verified session access token fields.
type Claims struct {
	UserID            uuid.UUID
	Email             string
	PreferredUsername string
	Name              string
	Picture           string
	ExpiresAt         time.Time
}

type jwtClaims struct {
	TokenUse          string `json:"token_use"`
	Email             string `json:"email,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	Name              string `json:"name,omitempty"`
	Picture           string `json:"picture,omitempty"`
	jwt.RegisteredClaims
}

// Config parameterises a Verifier.
type Config struct {
	// Issuer must match the token's iss claim.
	Issuer string
	// RequiredAudience, when non-empty, must be present in the token's aud claim.
	RequiredAudience string
	// CacheTTL bounds how long fetched keys are reused (default 5m).
	CacheTTL time.Duration
	// Leeway tolerates clock skew on exp/iat (default 60s).
	Leeway time.Duration
}

// Verifier validates session access tokens against a cached KeySource.
type Verifier struct {
	source           KeySource
	issuer           string
	requiredAudience string
	ttl              time.Duration
	leeway           time.Duration

	mu        sync.Mutex
	cache     map[string]*rsa.PublicKey
	fetchedAt time.Time
	group     singleflight.Group
}

// NewVerifier builds a Verifier.
func NewVerifier(source KeySource, cfg Config) *Verifier {
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = 5 * time.Minute
	}
	if cfg.Leeway <= 0 {
		cfg.Leeway = time.Minute
	}
	return &Verifier{
		source:           source,
		issuer:           cfg.Issuer,
		requiredAudience: strings.TrimSpace(cfg.RequiredAudience),
		ttl:              cfg.CacheTTL,
		leeway:           cfg.Leeway,
	}
}

// Verify validates raw and returns its claims. On a kid cache-miss it forces a
// single key refresh before failing, so rotation is picked up promptly.
func (v *Verifier) Verify(ctx context.Context, raw string) (Claims, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Claims{}, ErrInvalidToken
	}

	parsed, err := v.parse(ctx, raw, false)
	if errors.Is(err, ErrUnknownKey) {
		parsed, err = v.parse(ctx, raw, true)
	}
	return parsed, err
}

// VerifyContext validates raw and returns a child context carrying both the
// verified claims and the exact bearer value. Failed verification returns the
// original context unchanged, so an invalid credential is never retained.
func (v *Verifier) VerifyContext(ctx context.Context, raw string) (context.Context, error) {
	claims, err := v.Verify(ctx, raw)
	if err != nil {
		return ctx, err
	}
	ctx = WithClaims(ctx, claims)
	return withRawBearer(ctx, raw), nil
}

func (v *Verifier) parse(ctx context.Context, raw string, forceRefresh bool) (Claims, error) {
	keys, err := v.keys(ctx, forceRefresh)
	if err != nil {
		return Claims{}, err
	}

	var claims jwtClaims
	parserOptions := []jwt.ParserOption{
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(v.issuer),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(v.leeway),
	}
	if v.requiredAudience != "" {
		parserOptions = append(parserOptions, jwt.WithAudience(v.requiredAudience))
	}
	parser := jwt.NewParser(parserOptions...)

	_, err = parser.ParseWithClaims(raw, &claims, func(token *jwt.Token) (any, error) {
		if typ, _ := token.Header["typ"].(string); typ != sessionAccessTokenTyp {
			return nil, ErrInvalidToken
		}
		kid, _ := token.Header["kid"].(string)
		if strings.TrimSpace(kid) == "" {
			return nil, ErrInvalidToken
		}
		key, ok := keys[kid]
		if !ok {
			return nil, ErrUnknownKey
		}
		return key, nil
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrUnknownKey):
			return Claims{}, ErrUnknownKey
		case errors.Is(err, jwt.ErrTokenExpired):
			return Claims{}, ErrExpiredToken
		default:
			return Claims{}, errors.Join(ErrInvalidToken, err)
		}
	}

	if claims.TokenUse != sessionTokenUse {
		return Claims{}, ErrInvalidToken
	}
	userID, err := uuid.Parse(claims.Subject)
	if err != nil || userID == uuid.Nil {
		return Claims{}, ErrInvalidToken
	}

	out := Claims{
		UserID:            userID,
		Email:             claims.Email,
		PreferredUsername: claims.PreferredUsername,
		Name:              claims.Name,
		Picture:           claims.Picture,
	}
	if claims.ExpiresAt != nil {
		out.ExpiresAt = claims.ExpiresAt.Time
	}
	return out, nil
}

func (v *Verifier) keys(ctx context.Context, forceRefresh bool) (map[string]*rsa.PublicKey, error) {
	if !forceRefresh {
		v.mu.Lock()
		cache, fresh := v.cache, time.Since(v.fetchedAt) < v.ttl
		v.mu.Unlock()
		if cache != nil && fresh {
			return cache, nil
		}
	}

	// Coalesce concurrent refreshes so only one JWKS fetch is in flight at a
	// time, and never hold the lock across the network call.
	result, err, _ := v.group.Do("refresh", func() (any, error) {
		if !forceRefresh {
			// A concurrent refresh may have repopulated the cache while we waited.
			v.mu.Lock()
			cache, fresh := v.cache, time.Since(v.fetchedAt) < v.ttl
			v.mu.Unlock()
			if cache != nil && fresh {
				return cache, nil
			}
		}

		fetched, ferr := v.source.Keys(ctx)
		if ferr != nil {
			v.mu.Lock()
			cache := v.cache
			v.mu.Unlock()
			if cache != nil {
				// Serve the last-good keyset rather than failing closed on a
				// transient JWKS fetch error, but make the staleness visible.
				log.LogUnexpected(ctx, "jwtauth: JWKS fetch failed; serving cached keys", ferr.Error())
				return cache, nil
			}
			return nil, ferr
		}

		v.mu.Lock()
		v.cache = fetched
		v.fetchedAt = time.Now()
		v.mu.Unlock()
		return fetched, nil
	})
	if err != nil {
		return nil, err
	}
	return result.(map[string]*rsa.PublicKey), nil
}
