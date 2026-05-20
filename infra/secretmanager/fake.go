package secretmanager

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"

	gsm "sanzi.io/muid/pkg/shared/secretmanager"
)

type fakeVersion struct {
	payload  []byte
	disabled bool
}

// FakeSecretManager is an in-memory [SecretManager] for tests.
type FakeSecretManager struct {
	mu        sync.Mutex
	projectID string
	secrets   map[string][]fakeVersion
}

// NewFakeSecretManager returns an empty in-memory store scoped to projectID.
func NewFakeSecretManager(projectID string) SecretManager {
	return &FakeSecretManager{
		projectID: projectID,
		secrets:   make(map[string][]fakeVersion),
	}
}

func (f *FakeSecretManager) GetSecret(
	ctx context.Context,
	ref gsm.SecretRef,
) ([]byte, string, error) {
	secretName, err := resolveSecretName(f.projectID, ref.Name)
	if err != nil {
		return nil, "", err
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	versions, ok := f.secrets[secretName]
	if !ok || len(versions) == 0 {
		return nil, "", gsm.ErrSecretNotFound
	}

	version := resolveVersion(ref.Version)
	if version == "latest" {
		for i := len(versions) - 1; i >= 0; i-- {
			if !versions[i].disabled {
				id := strconv.Itoa(i + 1)
				return append([]byte(nil), versions[i].payload...), id, nil
			}
		}
		return nil, "", gsm.ErrVersionNotFound
	}

	idx, err := strconv.Atoi(version)
	if err != nil || idx < 1 || idx > len(versions) {
		return nil, "", gsm.ErrVersionNotFound
	}
	v := versions[idx-1]
	if v.disabled {
		return nil, "", gsm.ErrVersionDisabled
	}
	return append([]byte(nil), v.payload...), version, nil
}

func (f *FakeSecretManager) RotateSecret(
	ctx context.Context,
	ref gsm.SecretRef,
	payload []byte,
) (string, error) {
	if len(payload) == 0 {
		return "", gsm.ErrInvalidSecretRef
	}

	secretName, err := resolveSecretName(f.projectID, ref.Name)
	if err != nil {
		return "", err
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	versions := f.secrets[secretName]
	versions = append(versions, fakeVersion{payload: append([]byte(nil), payload...)})
	f.secrets[secretName] = versions

	return strconv.Itoa(len(versions)), nil
}

func (f *FakeSecretManager) RevokeSecret(ctx context.Context, ref gsm.SecretRef) error {
	secretName, err := resolveSecretName(f.projectID, ref.Name)
	if err != nil {
		return err
	}

	version := strings.TrimSpace(ref.Version)
	if version == "" || version == "latest" {
		return gsm.ErrInvalidSecretRef
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	versions, ok := f.secrets[secretName]
	if !ok || len(versions) == 0 {
		return gsm.ErrSecretNotFound
	}

	idx, err := strconv.Atoi(version)
	if err != nil || idx < 1 || idx > len(versions) {
		return gsm.ErrVersionNotFound
	}
	if versions[idx-1].disabled {
		return gsm.ErrVersionDisabled
	}
	versions[idx-1].disabled = true
	return nil
}

func (f *FakeSecretManager) Close() error {
	return nil
}

// SeedVersion inserts payload as version id for tests (id must be numeric).
func (f *FakeSecretManager) SeedVersion(secretID, version string, payload []byte) error {
	secretName, err := resolveSecretName(f.projectID, secretID)
	if err != nil {
		return err
	}
	idx, err := strconv.Atoi(version)
	if err != nil || idx < 1 {
		return fmt.Errorf("secretmanager fake: invalid version %q", version)
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	versions := f.secrets[secretName]
	for len(versions) < idx {
		versions = append(versions, fakeVersion{})
	}
	versions[idx-1] = fakeVersion{payload: append([]byte(nil), payload...)}
	f.secrets[secretName] = versions
	return nil
}

// EnabledVersions returns sorted enabled version ids for a secret.
func (f *FakeSecretManager) EnabledVersions(secretID string) ([]string, error) {
	secretName, err := resolveSecretName(f.projectID, secretID)
	if err != nil {
		return nil, err
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	versions, ok := f.secrets[secretName]
	if !ok {
		return nil, nil
	}

	var out []string
	for i, v := range versions {
		if !v.disabled {
			out = append(out, strconv.Itoa(i+1))
		}
	}
	sort.Strings(out)
	return out, nil
}

var _ SecretManager = (*FakeSecretManager)(nil)
