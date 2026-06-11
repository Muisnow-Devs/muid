package signature

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"

	"sanzi.io/muid/api/proto/authn/v1/certification"
	"sanzi.io/muid/pkg/log"
	gsm "sanzi.io/muid/pkg/shared/secretmanager"
)

const (
	defaultRotationPeriod = 30 * 24 * time.Hour
	defaultRefreshPeriod  = 15 * time.Minute
)

type secretBackedManager struct {
	secrets SecretManager
	cfg     ManagerConfig

	mu                sync.Mutex
	cacheByVersion    map[string]*cachedKey
	versionByKeyID    map[string]string
	currentVersion    string
	previousVersions  int
	rotationCancel    context.CancelFunc
	rotationDone      chan struct{}
	newRotationTicker func(time.Duration) rotationTicker
}

// NewSignatureManager returns a SecretManager-backed manager for OIDC signatures.
func NewSignatureManager(secrets SecretManager, cfg ManagerConfig) (SignatureManager, error) {
	if secrets == nil {
		return nil, ErrInvalidConfig
	}

	cfg.SecretName = strings.TrimSpace(cfg.SecretName)
	if cfg.SecretName == "" {
		return nil, ErrInvalidConfig
	}
	if cfg.KeyBits == 0 {
		cfg.KeyBits = defaultRSAKeyBits
	}
	if cfg.PreviousGenerations < 1 {
		cfg.PreviousGenerations = 1
	}
	if cfg.RotationPeriod == 0 {
		if cfg.ReadOnly {
			cfg.RotationPeriod = defaultRefreshPeriod
		} else {
			cfg.RotationPeriod = defaultRotationPeriod
		}
	}

	return &secretBackedManager{
		secrets:          secrets,
		cfg:              cfg,
		cacheByVersion:   make(map[string]*cachedKey),
		versionByKeyID:   make(map[string]string),
		previousVersions: cfg.PreviousGenerations,
		newRotationTicker: func(period time.Duration) rotationTicker {
			return realRotationTicker{ticker: time.NewTicker(period)}
		},
	}, nil
}

func (m *secretBackedManager) Start(ctx context.Context) error {
	if m.cfg.RotationPeriod < 0 {
		return nil
	}

	jobCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})

	m.mu.Lock()
	if m.rotationCancel != nil {
		m.mu.Unlock()
		cancel()
		return nil
	}
	m.rotationCancel = cancel
	m.rotationDone = done
	m.mu.Unlock()

	go func() {
		defer close(done)
		m.runRotationJob(jobCtx)
	}()

	return nil
}

func (m *secretBackedManager) Sign(ctx context.Context, data []byte) (Signature, error) {
	key, err := m.currentKey(ctx)
	if err != nil {
		return Signature{}, errors.Join(ErrSignFailed, err)
	}

	digest := sha256.Sum256(data)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key.key, crypto.SHA256, digest[:])
	if err != nil {
		return Signature{}, errors.Join(ErrSignFailed, err)
	}

	return Signature{
		KeyID:     key.keyID,
		Alg:       AlgorithmRS256,
		Signature: sig,
	}, nil
}

func (m *secretBackedManager) Verify(
	ctx context.Context,
	data []byte,
	sig Signature,
) (bool, error) {
	if sig.Alg != "" && sig.Alg != AlgorithmRS256 {
		return false, ErrUnsupportedAlgorithm
	}
	if len(sig.Signature) == 0 {
		return false, nil
	}

	keys, err := m.validationKeys(ctx, sig.KeyID)
	if err != nil {
		return false, errors.Join(ErrValidateFailed, err)
	}
	if len(keys) == 0 {
		return false, nil
	}

	digest := sha256.Sum256(data)
	for _, key := range keys {
		err = rsa.VerifyPKCS1v15(&key.key.PublicKey, crypto.SHA256, digest[:], sig.Signature)
		if err == nil {
			return true, nil
		}
	}
	return false, nil
}

func (m *secretBackedManager) PublicKeys(ctx context.Context) ([]*certification.PublicKey, error) {
	keys, err := m.keySet(ctx)
	if err != nil {
		return nil, errors.Join(ErrPublicKeyUnavailable, err)
	}

	out := make([]*certification.PublicKey, 0, len(keys))
	for _, key := range keys {
		out = append(out, clonePublicKey(key.publicKey))
	}
	return out, nil
}

func (m *secretBackedManager) RotateSecret(ctx context.Context) (KeyMetadata, error) {
	if m.cfg.ReadOnly {
		return KeyMetadata{}, ErrReadOnly
	}

	payload, err := generatePrivateKeyPEM(m.cfg.KeyBits)
	if err != nil {
		return KeyMetadata{}, err
	}

	version, err := m.secrets.RotateSecret(ctx, gsm.SecretRef{Name: m.cfg.SecretName}, payload)
	if err != nil {
		return KeyMetadata{}, errors.Join(ErrRotateFailed, err)
	}

	key, err := m.cachePayload(version, payload)
	if err != nil {
		return KeyMetadata{}, errors.Join(ErrRotateFailed, err)
	}

	m.mu.Lock()
	m.currentVersion = version
	m.mu.Unlock()

	return KeyMetadata{
		KeyID:   key.keyID,
		Version: version,
		Alg:     AlgorithmRS256,
	}, nil
}

func (m *secretBackedManager) RevokeSecret(ctx context.Context, keyID string) error {
	if m.cfg.ReadOnly {
		return ErrReadOnly
	}

	version, err := m.versionForKeyID(ctx, keyID)
	if err != nil {
		return errors.Join(ErrRevokeFailed, err)
	}

	err = m.secrets.RevokeSecret(ctx, gsm.SecretRef{Name: m.cfg.SecretName, Version: version})
	if err != nil {
		return errors.Join(ErrRevokeFailed, err)
	}

	m.mu.Lock()
	delete(m.cacheByVersion, version)
	delete(m.versionByKeyID, strings.TrimSpace(keyID))
	if m.currentVersion == version {
		m.currentVersion = ""
	}
	m.mu.Unlock()

	return nil
}

func (m *secretBackedManager) Close() error {
	m.mu.Lock()
	cancel := m.rotationCancel
	done := m.rotationDone
	m.rotationCancel = nil
	m.rotationDone = nil
	m.mu.Unlock()

	if cancel != nil {
		cancel()
		<-done
	}

	return m.secrets.Close()
}

func (m *secretBackedManager) runRotationJob(ctx context.Context) {
	step := func(ctx context.Context) error {
		_, err := m.RotateSecret(ctx)
		return err
	}
	failureMessage := "signature rotate secret"
	if m.cfg.ReadOnly {
		step = m.refreshCurrent
		failureMessage = "signature refresh secret"
	}

	job := rotationJob{
		period:    m.cfg.RotationPeriod,
		newTicker: m.newRotationTicker,
		rotate:    step,
		logFailure: func(ctx context.Context, err error) {
			log.LogUnexpected(ctx, failureMessage, err.Error())
		},
	}
	job.run(ctx)
}

// refreshCurrent re-resolves the latest secret version, bypassing the
// current-version cache short-circuit, so follower managers observe
// rotations performed by the owning service.
func (m *secretBackedManager) refreshCurrent(ctx context.Context) error {
	payload, version, err := m.secrets.GetSecret(
		ctx,
		gsm.SecretRef{Name: m.cfg.SecretName, Version: "latest"},
	)
	if err != nil {
		return errors.Join(ErrSecretUnavailable, err)
	}

	m.mu.Lock()
	cached := m.cacheByVersion[version]
	m.mu.Unlock()
	if cached == nil {
		_, err = m.cachePayload(version, payload)
		if err != nil {
			return err
		}
	}

	m.mu.Lock()
	m.currentVersion = version
	m.mu.Unlock()
	return nil
}

func (m *secretBackedManager) currentKey(ctx context.Context) (*cachedKey, error) {
	m.mu.Lock()
	if m.currentVersion != "" {
		if key := m.cacheByVersion[m.currentVersion]; key != nil {
			m.mu.Unlock()
			return key, nil
		}
	}
	m.mu.Unlock()

	payload, version, err := m.secrets.GetSecret(
		ctx,
		gsm.SecretRef{Name: m.cfg.SecretName, Version: "latest"},
	)
	if err != nil {
		return nil, errors.Join(ErrSecretUnavailable, err)
	}

	m.mu.Lock()
	if key := m.cacheByVersion[version]; key != nil {
		m.currentVersion = version
		m.mu.Unlock()
		return key, nil
	}
	m.mu.Unlock()

	key, err := m.cachePayload(version, payload)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	m.currentVersion = version
	m.mu.Unlock()
	return key, nil
}

func (m *secretBackedManager) keySet(ctx context.Context) ([]*cachedKey, error) {
	current, err := m.currentKey(ctx)
	if err != nil {
		return nil, err
	}

	keys := []*cachedKey{current}
	versions := previousVersionIDs(current.version, m.previousVersions)
	for _, version := range versions {
		key, loadErr := m.loadVersion(ctx, version)
		if errors.Is(loadErr, gsm.ErrVersionDisabled) ||
			errors.Is(loadErr, gsm.ErrVersionNotFound) {
			continue
		}
		if loadErr != nil {
			return nil, loadErr
		}
		keys = append(keys, key)
	}
	return keys, nil
}

func (m *secretBackedManager) validationKeys(
	ctx context.Context,
	keyID string,
) ([]*cachedKey, error) {
	keyID = strings.TrimSpace(keyID)
	if keyID == "" {
		return m.keySet(ctx)
	}

	version, err := m.versionForKeyID(ctx, keyID)
	if err != nil {
		if errors.Is(err, ErrKeyNotFound) {
			return nil, nil
		}
		return nil, err
	}

	key, err := m.loadVersion(ctx, version)
	if errors.Is(err, gsm.ErrVersionDisabled) || errors.Is(err, gsm.ErrVersionNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return []*cachedKey{key}, nil
}

func (m *secretBackedManager) versionForKeyID(ctx context.Context, keyID string) (string, error) {
	keyID = strings.TrimSpace(keyID)
	if keyID == "" {
		return "", ErrKeyNotFound
	}

	m.mu.Lock()
	version := m.versionByKeyID[keyID]
	m.mu.Unlock()
	if version != "" {
		return version, nil
	}

	_, err := m.keySet(ctx)
	if err != nil {
		return "", err
	}

	m.mu.Lock()
	version = m.versionByKeyID[keyID]
	m.mu.Unlock()
	if version == "" {
		return "", ErrKeyNotFound
	}
	return version, nil
}

func (m *secretBackedManager) loadVersion(ctx context.Context, version string) (*cachedKey, error) {
	version = strings.TrimSpace(version)
	if version == "" {
		return nil, gsm.ErrInvalidSecretRef
	}

	m.mu.Lock()
	if key := m.cacheByVersion[version]; key != nil {
		m.mu.Unlock()
		return key, nil
	}
	m.mu.Unlock()

	payload, resolvedVersion, err := m.secrets.GetSecret(ctx, gsm.SecretRef{
		Name:    m.cfg.SecretName,
		Version: version,
	})
	if err != nil {
		return nil, errors.Join(ErrSecretUnavailable, err)
	}
	if resolvedVersion != "" {
		version = resolvedVersion
	}

	return m.cachePayload(version, payload)
}

func (m *secretBackedManager) cachePayload(version string, payload []byte) (*cachedKey, error) {
	privateKey, err := parsePrivateKey(payload)
	if err != nil {
		return nil, err
	}

	kid := keyID(m.cfg.SecretName, version)
	publicKey, err := publicKeyFromPrivate(kid, privateKey)
	if err != nil {
		return nil, err
	}

	key := &cachedKey{
		key:       privateKey,
		version:   version,
		keyID:     kid,
		publicKey: publicKey,
	}

	m.mu.Lock()
	m.cacheByVersion[version] = key
	m.versionByKeyID[kid] = version
	m.mu.Unlock()
	return key, nil
}

func previousVersionIDs(current string, generations int) []string {
	currentNumber, err := strconv.Atoi(strings.TrimSpace(current))
	if err != nil || currentNumber <= 1 {
		return nil
	}
	if generations < 1 {
		generations = 1
	}

	out := make([]string, 0, generations)
	for version := currentNumber - 1; version >= 1 && len(out) < generations; version-- {
		out = append(out, strconv.Itoa(version))
	}
	return out
}

var _ SignatureManager = (*secretBackedManager)(nil)
