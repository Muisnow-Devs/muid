package secretmanager

import (
	"context"
	"fmt"
	"strings"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"google.golang.org/api/option"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	gsm "sanzi.io/muid/pkg/shared/secretmanager"
)

// GCPConfig holds client settings for [NewGCPSecretManager].
type GCPConfig struct {
	// ProjectID is the GCP project that owns secrets when Name is a short secret id.
	ProjectID string
	// CredentialsFile is optional; empty uses Application Default Credentials.
	CredentialsFile string
}

// GCPSecretManager implements [SecretManager] with Google Secret Manager.
type GCPSecretManager struct {
	projectID string
	client    *secretmanager.Client
}

// NewGCPSecretManager dials GSM and returns a [SecretManager].
func NewGCPSecretManager(ctx context.Context, cfg GCPConfig) (SecretManager, error) {
	projectID := strings.TrimSpace(cfg.ProjectID)
	if projectID == "" {
		return nil, gsm.ErrEmptyProjectID
	}

	var opts []option.ClientOption
	credentialsFile := strings.TrimSpace(cfg.CredentialsFile)
	if credentialsFile != "" {
		opts = append(opts, option.WithCredentialsFile(credentialsFile))
	}

	client, err := secretmanager.NewClient(ctx, opts...)
	if err != nil {
		return nil, err
	}

	return &GCPSecretManager{
		projectID: projectID,
		client:    client,
	}, nil
}

func (g *GCPSecretManager) GetSecret(
	ctx context.Context,
	ref gsm.SecretRef,
) ([]byte, string, error) {
	secretName, err := resolveSecretName(g.projectID, ref.Name)
	if err != nil {
		return nil, "", err
	}

	versionName, err := versionResourceName(secretName, ref.Version)
	if err != nil {
		return nil, "", err
	}

	resp, err := g.client.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: versionName,
	})
	if err != nil {
		return nil, "", mapGCPError(err)
	}

	payload := resp.GetPayload()
	if payload == nil {
		return nil, "", fmt.Errorf("secretmanager: empty payload for %s", versionName)
	}

	version := versionIDFromResourceName(resp.GetName())
	return payload.GetData(), version, nil
}

func (g *GCPSecretManager) RotateSecret(
	ctx context.Context,
	ref gsm.SecretRef,
	payload []byte,
) (string, error) {
	if len(payload) == 0 {
		return "", gsm.ErrInvalidSecretRef
	}

	secretName, err := resolveSecretName(g.projectID, ref.Name)
	if err != nil {
		return "", err
	}

	resp, err := g.client.AddSecretVersion(ctx, &secretmanagerpb.AddSecretVersionRequest{
		Parent: secretName,
		Payload: &secretmanagerpb.SecretPayload{
			Data: payload,
		},
	})
	if err != nil {
		return "", mapGCPError(err)
	}

	version := versionIDFromResourceName(resp.GetName())
	if version == "" {
		return "", fmt.Errorf("secretmanager: missing version in add response")
	}
	return version, nil
}

// RevokeSecret calls GCP DisableSecretVersion on ref.Version.
// The version is disabled (not destroyed): it cannot be read, but remains for audit.
// Use an explicit numeric version; "latest" is rejected.
func (g *GCPSecretManager) RevokeSecret(ctx context.Context, ref gsm.SecretRef) error {
	secretName, err := resolveSecretName(g.projectID, ref.Name)
	if err != nil {
		return err
	}

	versionName, err := explicitVersionResourceName(secretName, ref.Version)
	if err != nil {
		return err
	}

	_, err = g.client.DisableSecretVersion(ctx, &secretmanagerpb.DisableSecretVersionRequest{
		Name: versionName,
	})
	if err != nil {
		return mapGCPError(err)
	}
	return nil
}

func (g *GCPSecretManager) Close() error {
	if g.client == nil {
		return nil
	}
	return g.client.Close()
}

func mapGCPError(err error) error {
	if err == nil {
		return nil
	}
	st, ok := status.FromError(err)
	if !ok {
		return err
	}
	switch st.Code() {
	case codes.NotFound:
		msg := strings.ToLower(st.Message())
		if strings.Contains(msg, "version") {
			return gsm.ErrVersionNotFound
		}
		return gsm.ErrSecretNotFound
	case codes.FailedPrecondition:
		return gsm.ErrVersionDisabled
	default:
		return err
	}
}

// DestroySecretVersion permanently destroys a version (irreversible).
// It is not part of [SecretManager]; callers may use this helper when purge is required.
func (g *GCPSecretManager) DestroySecretVersion(ctx context.Context, ref gsm.SecretRef) error {
	secretName, err := resolveSecretName(g.projectID, ref.Name)
	if err != nil {
		return err
	}

	versionName, err := explicitVersionResourceName(secretName, ref.Version)
	if err != nil {
		return err
	}

	_, err = g.client.DestroySecretVersion(ctx, &secretmanagerpb.DestroySecretVersionRequest{
		Name: versionName,
	})
	if err != nil {
		return mapGCPError(err)
	}
	return nil
}

var _ SecretManager = (*GCPSecretManager)(nil)
