package authzgrpc

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"sanzi.io/muid/api/proto/authz/v1/certification"
	"sanzi.io/muid/internal/signature"
)

type fakeSignatureManager struct {
	keys []*certification.PublicKey
	err  error
}

func (f fakeSignatureManager) Start(context.Context) error {
	return nil
}

func (f fakeSignatureManager) Sign(context.Context, []byte) (signature.Signature, error) {
	return signature.Signature{}, nil
}

func (f fakeSignatureManager) Verify(context.Context, []byte, signature.Signature) (bool, error) {
	return false, nil
}

func (f fakeSignatureManager) PublicKeys(context.Context) ([]*certification.PublicKey, error) {
	return f.keys, f.err
}

func (f fakeSignatureManager) RotateSecret(context.Context) (signature.KeyMetadata, error) {
	return signature.KeyMetadata{}, nil
}

func (f fakeSignatureManager) RevokeSecret(context.Context, string) error {
	return nil
}

func (f fakeSignatureManager) Close() error {
	return nil
}

func TestGRPCHandlerGetPublicKeys(t *testing.T) {
	t.Parallel()

	key := &certification.PublicKey{}
	key.SetKid("8d529c15-3743-4c79-8919-86fa7afbd0b5")
	key.SetKty("RSA")
	key.SetAlg(signature.AlgorithmRS256)
	key.SetUse("sig")

	handler := &GRPCHandler{
		signing: fakeSignatureManager{keys: []*certification.PublicKey{key}},
	}

	out, err := handler.GetPublicKeys(context.Background(), nil)
	if err != nil {
		t.Fatalf("GetPublicKeys: %v", err)
	}
	if len(out.GetPublicKeys()) != 1 || out.GetPublicKeys()[0].GetKid() != key.GetKid() {
		t.Fatalf("GetPublicKeys = %v", out.GetPublicKeys())
	}
}

func TestGRPCHandlerGetPublicKeysUnavailable(t *testing.T) {
	t.Parallel()

	handler := &GRPCHandler{}
	_, err := handler.GetPublicKeys(context.Background(), nil)
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("GetPublicKeys code = %v, want %v", status.Code(err), codes.Unavailable)
	}
}

func TestGRPCHandlerGetPublicKeysInternalError(t *testing.T) {
	t.Parallel()

	handler := &GRPCHandler{
		signing: fakeSignatureManager{err: errors.New("boom")},
	}
	_, err := handler.GetPublicKeys(context.Background(), nil)
	if status.Code(err) != codes.Internal {
		t.Fatalf("GetPublicKeys code = %v, want %v", status.Code(err), codes.Internal)
	}
}
