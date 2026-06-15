package jwtauth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
	"time"

	"google.golang.org/grpc"

	authnpb "sanzi.io/muid/api/proto/authn/v1"
	"sanzi.io/muid/pkg/log"
)

// AuthnPublicKeyClient is the subset of authnpb.AuthnServiceClient used to
// source JWKS keys; the generated client satisfies it structurally.
type AuthnPublicKeyClient interface {
	GetPublicKeys(
		ctx context.Context,
		in *authnpb.GetPublicKeysRequest,
		opts ...grpc.CallOption,
	) (*authnpb.GetPublicKeysResponse, error)
}

// authnKeySource fetches RSA verification keys from AuthnService.GetPublicKeys.
type authnKeySource struct {
	client AuthnPublicKeyClient
}

// NewAuthnKeySource builds a KeySource backed by an authn service client.
func NewAuthnKeySource(client AuthnPublicKeyClient) KeySource {
	return &authnKeySource{client: client}
}

// NewAuthnVerifier builds a Verifier that sources its JWKS from authn's
// GetPublicKeys, with the given expected issuer and key-cache TTL. It is the
// single constructor the gateways use instead of re-wiring NewVerifier +
// NewAuthnKeySource + Config each.
func NewAuthnVerifier(client AuthnPublicKeyClient, issuer string, cacheTTL time.Duration) *Verifier {
	return NewVerifier(NewAuthnKeySource(client), Config{Issuer: issuer, CacheTTL: cacheTTL})
}

// Keys implements KeySource, converting the JWKS RSA entries into public keys.
func (s *authnKeySource) Keys(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	resp, err := s.client.GetPublicKeys(ctx, &authnpb.GetPublicKeysRequest{})
	if err != nil {
		return nil, err
	}

	out := make(map[string]*rsa.PublicKey)
	for _, pk := range resp.GetPublicKeys() {
		if !strings.EqualFold(pk.GetKty(), "RSA") {
			continue
		}
		kid := strings.TrimSpace(pk.GetKid())
		if kid == "" {
			continue
		}
		key, err := rsaPublicKey(pk.GetN(), pk.GetE())
		if err != nil {
			// Skip unusable keys, but surface it: a silently dropped key turns
			// into an auth outage with no signal.
			log.LogUnexpected(ctx, "jwtauth: skipping unusable JWKS key", err.Error())
			continue
		}
		out[kid] = key
	}
	// Treat a successful fetch that yields nothing usable as an error so the
	// verifier serves its last-good cache instead of caching an empty keyset.
	if len(out) == 0 {
		return nil, ErrNoUsableKeys
	}
	return out, nil
}

// minRSAModulusBits is a defensive floor that rejects degenerate/undersized
// moduli at the boundary where external bytes become a verification key.
const minRSAModulusBits = 2048

// errUnusableKey is returned by rsaPublicKey for a malformed or degenerate key.
var errUnusableKey = errors.New("jwtauth: unusable RSA key")

// rsaPublicKey reconstructs an RSA public key from base64url modulus/exponent.
func rsaPublicKey(nB64, eB64 string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(nB64, "="))
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(eB64, "="))
	if err != nil {
		return nil, err
	}
	// The exponent must be present and fit a plain int (no overflow from an
	// over-long value).
	if len(eBytes) == 0 || len(eBytes) > 8 {
		return nil, errUnusableKey
	}
	e := 0
	for _, b := range eBytes {
		e = e<<8 | int(b)
	}
	if e < 2 {
		return nil, errUnusableKey
	}
	n := new(big.Int).SetBytes(nBytes)
	if n.Sign() <= 0 || n.BitLen() < minRSAModulusBits {
		return nil, errUnusableKey
	}
	return &rsa.PublicKey{N: n, E: e}, nil
}
