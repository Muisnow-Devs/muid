package signature

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	gcpsecretmanager "sanzi.io/muid/infra/secretmanager"
)

type countingSecretManager struct {
	inner SecretManager

	mu             sync.Mutex
	getCount       int
	rotateCount    int
	rotateFailures int
	rotateErr      error
}

func (c *countingSecretManager) GetSecret(
	ctx context.Context,
	ref SecretRef,
) ([]byte, string, error) {
	c.mu.Lock()
	c.getCount++
	c.mu.Unlock()

	return c.inner.GetSecret(ctx, ref)
}

func (c *countingSecretManager) RotateSecret(
	ctx context.Context,
	ref SecretRef,
	payload []byte,
) (string, error) {
	c.mu.Lock()
	c.rotateCount++
	if c.rotateFailures > 0 {
		c.rotateFailures--
		err := c.rotateErr
		c.mu.Unlock()
		if err == nil {
			err = errors.New("rotate failed")
		}
		return "", err
	}
	c.mu.Unlock()

	return c.inner.RotateSecret(ctx, ref, payload)
}

func (c *countingSecretManager) RevokeSecret(ctx context.Context, ref SecretRef) error {
	return c.inner.RevokeSecret(ctx, ref)
}

func (c *countingSecretManager) Close() error {
	return c.inner.Close()
}

func (c *countingSecretManager) GetCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.getCount
}

func (c *countingSecretManager) RotateCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.rotateCount
}

type manualRotationTicker struct {
	ch       chan time.Time
	stopOnce sync.Once
	stopped  chan struct{}
}

func newManualRotationTicker() *manualRotationTicker {
	return &manualRotationTicker{
		ch:      make(chan time.Time, 4),
		stopped: make(chan struct{}),
	}
}

func (m *manualRotationTicker) C() <-chan time.Time {
	return m.ch
}

func (m *manualRotationTicker) Stop() {
	m.stopOnce.Do(func() {
		close(m.stopped)
	})
}

func (m *manualRotationTicker) Tick() {
	m.ch <- time.Now()
}

func newTestManager(t *testing.T) (context.Context, SignatureManager) {
	t.Helper()

	ctx := context.Background()
	manager, err := NewSignatureManager(
		gcpsecretmanager.NewFakeSecretManager("test-project"),
		ManagerConfig{
			SecretName:          "oidc-signing-key",
			PreviousGenerations: 1,
		},
	)
	if err != nil {
		t.Fatalf("NewSignatureManager: %v", err)
	}
	return ctx, manager
}

func TestSignatureManagerSignVerify(t *testing.T) {
	t.Parallel()

	ctx, manager := newTestManager(t)
	metadata, err := manager.RotateSecret(ctx)
	if err != nil {
		t.Fatalf("RotateSecret: %v", err)
	}

	sig, err := manager.Sign(ctx, []byte("payload"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if sig.KeyID != metadata.KeyID || sig.Alg != AlgorithmRS256 {
		t.Fatalf(
			"signature metadata = (%q, %q), want (%q, %q)",
			sig.KeyID,
			sig.Alg,
			metadata.KeyID,
			AlgorithmRS256,
		)
	}

	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{name: "valid", data: []byte("payload"), want: true},
		{name: "wrong data", data: []byte("other"), want: false},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			valid, err := manager.Verify(ctx, tc.data, sig)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if valid != tc.want {
				t.Fatalf("Verify = %v, want %v", valid, tc.want)
			}
		})
	}
}

func TestSignatureManagerPublicKeysDoNotExposePrivateMaterial(t *testing.T) {
	t.Parallel()

	ctx, manager := newTestManager(t)
	metadata, err := manager.RotateSecret(ctx)
	if err != nil {
		t.Fatalf("RotateSecret: %v", err)
	}

	keys, err := manager.PublicKeys(ctx)
	if err != nil {
		t.Fatalf("PublicKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("PublicKeys len = %d, want 1", len(keys))
	}
	key := keys[0]
	if key.GetKid() != metadata.KeyID || key.GetKty() != "RSA" || key.GetAlg() != AlgorithmRS256 ||
		key.GetUse() != "sig" {
		t.Fatalf(
			"public key metadata = kid:%q kty:%q alg:%q use:%q",
			key.GetKid(),
			key.GetKty(),
			key.GetAlg(),
			key.GetUse(),
		)
	}
	if key.GetN() == "" || key.GetE() == "" {
		t.Fatalf("public key missing RSA coordinates")
	}
	if key.GetCrv() != "" || key.GetX() != "" || key.GetY() != "" {
		t.Fatalf(
			"public key exposed unexpected EC/private fields: crv=%q x=%q y=%q",
			key.GetCrv(),
			key.GetX(),
			key.GetY(),
		)
	}

	originalN := key.GetN()
	key.SetN("")
	keys, err = manager.PublicKeys(ctx)
	if err != nil {
		t.Fatalf("PublicKeys after mutation: %v", err)
	}
	if keys[0].GetN() != originalN {
		t.Fatalf("PublicKeys returned mutable cached key")
	}
}

func TestSignatureManagerRotationAllowsPreviousGeneration(t *testing.T) {
	t.Parallel()

	ctx, manager := newTestManager(t)
	_, err := manager.RotateSecret(ctx)
	if err != nil {
		t.Fatalf("RotateSecret first: %v", err)
	}
	oldSig, err := manager.Sign(ctx, []byte("payload"))
	if err != nil {
		t.Fatalf("Sign old: %v", err)
	}

	_, err = manager.RotateSecret(ctx)
	if err != nil {
		t.Fatalf("RotateSecret second: %v", err)
	}

	valid, err := manager.Verify(ctx, []byte("payload"), oldSig)
	if err != nil {
		t.Fatalf("Verify old generation: %v", err)
	}
	if !valid {
		t.Fatal("Verify old generation = false, want true")
	}

	keys, err := manager.PublicKeys(ctx)
	if err != nil {
		t.Fatalf("PublicKeys: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("PublicKeys len = %d, want 2", len(keys))
	}
}

func TestSignatureManagerRevokedGenerationDoesNotVerify(t *testing.T) {
	t.Parallel()

	ctx, manager := newTestManager(t)
	first, err := manager.RotateSecret(ctx)
	if err != nil {
		t.Fatalf("RotateSecret first: %v", err)
	}
	oldSig, err := manager.Sign(ctx, []byte("payload"))
	if err != nil {
		t.Fatalf("Sign old: %v", err)
	}
	_, err = manager.RotateSecret(ctx)
	if err != nil {
		t.Fatalf("RotateSecret second: %v", err)
	}

	err = manager.RevokeSecret(ctx, first.KeyID)
	if err != nil {
		t.Fatalf("RevokeSecret: %v", err)
	}

	valid, err := manager.Verify(ctx, []byte("payload"), oldSig)
	if err != nil {
		t.Fatalf("Verify revoked generation: %v", err)
	}
	if valid {
		t.Fatal("Verify revoked generation = true, want false")
	}
}

func TestSignatureManagerCachesKeysInternally(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := &countingSecretManager{inner: gcpsecretmanager.NewFakeSecretManager("test-project")}
	manager, err := NewSignatureManager(store, ManagerConfig{SecretName: "oidc-signing-key"})
	if err != nil {
		t.Fatalf("NewSignatureManager: %v", err)
	}

	_, err = manager.RotateSecret(ctx)
	if err != nil {
		t.Fatalf("RotateSecret: %v", err)
	}
	sig, err := manager.Sign(ctx, []byte("payload"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	_, err = manager.PublicKeys(ctx)
	if err != nil {
		t.Fatalf("PublicKeys: %v", err)
	}
	_, err = manager.PublicKeys(ctx)
	if err != nil {
		t.Fatalf("PublicKeys second: %v", err)
	}
	valid, err := manager.Verify(ctx, []byte("payload"), sig)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !valid {
		t.Fatal("Verify = false, want true")
	}
	if store.GetCount() != 0 {
		t.Fatalf("GetSecret calls = %d, want 0", store.GetCount())
	}
}

func TestSignatureManagerStartRotatesOnTicker(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	store := &countingSecretManager{inner: gcpsecretmanager.NewFakeSecretManager("test-project")}
	manager, ticker, ready, period := newManualRotationManager(t, store)

	err := manager.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	<-ready
	if *period != time.Hour {
		t.Fatalf("rotation period = %v, want %v", *period, time.Hour)
	}

	ticker.Tick()
	waitForRotateCount(t, store, 1)

	err = manager.Close()
	if err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestSignatureManagerRotationJobStopsAfterContextCancel(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	store := &countingSecretManager{inner: gcpsecretmanager.NewFakeSecretManager("test-project")}
	manager, ticker, ready, _ := newManualRotationManager(t, store)

	err := manager.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	<-ready

	done := manager.rotationJobDone()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("rotation job did not stop after context cancel")
	}

	before := store.RotateCount()
	ticker.Tick()
	if got := store.RotateCount(); got != before {
		t.Fatalf("RotateCount after cancel = %d, want %d", got, before)
	}

	err = manager.Close()
	if err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestSignatureManagerRotationJobRetriesAfterFailure(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	store := &countingSecretManager{
		inner:          gcpsecretmanager.NewFakeSecretManager("test-project"),
		rotateFailures: 1,
		rotateErr:      errors.New("secret manager unavailable"),
	}
	manager, ticker, ready, _ := newManualRotationManager(t, store)

	err := manager.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	<-ready

	ticker.Tick()
	waitForRotateCount(t, store, 1)
	ticker.Tick()
	waitForRotateCount(t, store, 2)

	err = manager.Close()
	if err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestSignatureManagerExistingSecretLoadsOnce(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := &countingSecretManager{inner: gcpsecretmanager.NewFakeSecretManager("test-project")}
	seeder, err := NewSignatureManager(store.inner, ManagerConfig{SecretName: "oidc-signing-key"})
	if err != nil {
		t.Fatalf("New seeder: %v", err)
	}
	_, err = seeder.RotateSecret(ctx)
	if err != nil {
		t.Fatalf("Seed RotateSecret: %v", err)
	}

	manager, err := NewSignatureManager(store, ManagerConfig{SecretName: "oidc-signing-key"})
	if err != nil {
		t.Fatalf("NewSignatureManager: %v", err)
	}
	_, err = manager.Sign(ctx, []byte("payload"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	_, err = manager.Sign(ctx, []byte("payload"))
	if err != nil {
		t.Fatalf("Sign second: %v", err)
	}
	if store.GetCount() != 1 {
		t.Fatalf("GetSecret calls = %d, want 1", store.GetCount())
	}
}

func newManualRotationManager(
	t *testing.T,
	store *countingSecretManager,
) (*secretBackedManager, *manualRotationTicker, chan struct{}, *time.Duration) {
	t.Helper()

	managerIface, err := NewSignatureManager(store, ManagerConfig{
		SecretName:     "oidc-signing-key",
		RotationPeriod: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewSignatureManager: %v", err)
	}

	manager := managerIface.(*secretBackedManager)
	ticker := newManualRotationTicker()
	ready := make(chan struct{})
	var period time.Duration
	manager.newRotationTicker = func(p time.Duration) rotationTicker {
		period = p
		close(ready)
		return ticker
	}
	return manager, ticker, ready, &period
}

func (m *secretBackedManager) rotationJobDone() <-chan struct{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.rotationDone
}

func waitForRotateCount(t *testing.T, store *countingSecretManager, want int) {
	t.Helper()

	deadline := time.After(time.Second)
	for {
		if store.RotateCount() >= want {
			return
		}

		select {
		case <-deadline:
			t.Fatalf("RotateCount = %d, want at least %d", store.RotateCount(), want)
		default:
			time.Sleep(time.Millisecond)
		}
	}
}

func TestSignatureManagerRevokeUnknownKey(t *testing.T) {
	t.Parallel()

	ctx, manager := newTestManager(t)
	_, err := manager.RotateSecret(ctx)
	if err != nil {
		t.Fatalf("RotateSecret: %v", err)
	}

	err = manager.RevokeSecret(ctx, "00000000-0000-0000-0000-000000000000")
	if err == nil {
		t.Fatal("RevokeSecret err = nil, want error")
	}
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("RevokeSecret err = %v, want ErrKeyNotFound", err)
	}
}
