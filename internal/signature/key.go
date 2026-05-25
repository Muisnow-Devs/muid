package signature

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	"sanzi.io/muid/api/proto/authz/v1/certification"
)

const (
	// AlgorithmRS256 is the OIDC signing algorithm currently supported by SignatureManager.
	AlgorithmRS256 = "RS256"

	defaultRSAKeyBits = 2048
	minRSAKeyBits     = 2048

	jwkKeyTypeRSA = "RSA"
	jwkUseSig     = "sig"
)

type cachedKey struct {
	key       *rsa.PrivateKey
	version   string
	keyID     string
	publicKey *certification.PublicKey
}

func generatePrivateKeyPEM(bits int) ([]byte, error) {
	if bits < minRSAKeyBits {
		bits = defaultRSAKeyBits
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, errors.Join(ErrRotateFailed, err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, errors.Join(ErrRotateFailed, err)
	}

	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}
	return pem.EncodeToMemory(block), nil
}

func parsePrivateKey(payload []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(payload)
	if block == nil {
		return nil, ErrInvalidKey
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		rsaKey, ok := privateKey.(*rsa.PrivateKey)
		if !ok {
			return nil, ErrInvalidKey
		}
		return rsaKey, nil
	}

	rsaKey, pkcs1Err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if pkcs1Err != nil {
		return nil, errors.Join(ErrInvalidKey, err, pkcs1Err)
	}
	return rsaKey, nil
}

func keyID(secretName, version string) string {
	source := strings.TrimSpace(secretName) + "\x00" + strings.TrimSpace(version)
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(source)).String()
}

func publicKeyFromPrivate(
	keyID string,
	privateKey *rsa.PrivateKey,
) (*certification.PublicKey, error) {
	if privateKey == nil {
		return nil, ErrInvalidKey
	}

	pub := privateKey.PublicKey
	if pub.N == nil || pub.E == 0 {
		return nil, ErrInvalidKey
	}

	out := &certification.PublicKey{}
	out.SetKid(keyID)
	out.SetKty(jwkKeyTypeRSA)
	out.SetAlg(AlgorithmRS256)
	out.SetUse(jwkUseSig)
	out.SetN(base64.RawURLEncoding.EncodeToString(pub.N.Bytes()))
	out.SetE(base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()))
	return out, nil
}

func clonePublicKey(in *certification.PublicKey) *certification.PublicKey {
	if in == nil {
		return nil
	}

	out := &certification.PublicKey{}
	out.SetKid(in.GetKid())
	out.SetKty(in.GetKty())
	out.SetAlg(in.GetAlg())
	out.SetUse(in.GetUse())
	out.SetN(in.GetN())
	out.SetE(in.GetE())
	out.SetCrv(in.GetCrv())
	out.SetX(in.GetX())
	out.SetY(in.GetY())
	if in.HasNotBefore() {
		out.SetNotBefore(timestamppb.New(in.GetNotBefore().AsTime()))
	}
	if in.HasNotAfter() {
		out.SetNotAfter(timestamppb.New(in.GetNotAfter().AsTime()))
	}
	return out
}
