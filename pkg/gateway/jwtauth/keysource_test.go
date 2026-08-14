package jwtauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"testing"

	"google.golang.org/grpc"

	authnpb "sanzi.io/muid/api/proto/authn/v1"
	certificationpb "sanzi.io/muid/api/proto/authn/v1/certification"
)

type fakeSigningKeyClient struct {
	authnpb.SigningKeyServiceClient
	response *authnpb.GetPublicKeysResponse
}

func (f *fakeSigningKeyClient) GetPublicKeys(
	context.Context,
	*authnpb.GetPublicKeysRequest,
	...grpc.CallOption,
) (*authnpb.GetPublicKeysResponse, error) {
	return f.response, nil
}

var _ SigningKeyClient = (*fakeSigningKeyClient)(nil)

func TestAuthnKeySourceUsesSigningKeyServiceClient(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, minRSAModulusBits)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	publicKey := &certificationpb.PublicKey{}
	publicKey.SetKid("current")
	publicKey.SetKty("RSA")
	publicKey.SetN(base64.RawURLEncoding.EncodeToString(privateKey.N.Bytes()))
	publicKey.SetE(base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privateKey.E)).Bytes()))
	response := &authnpb.GetPublicKeysResponse{}
	response.SetPublicKeys([]*certificationpb.PublicKey{publicKey})

	keys, err := NewAuthnKeySource(&fakeSigningKeyClient{response: response}).Keys(t.Context())
	if err != nil {
		t.Fatalf("Keys() error = %v", err)
	}
	got := keys["current"]
	if got == nil {
		t.Fatal("Keys() missing current signing key")
	}
	if got.E != privateKey.E || got.N.Cmp(privateKey.N) != 0 {
		t.Fatal("Keys() returned a different RSA public key")
	}
}
