package app

import (
	"errors"
	"io"

	"google.golang.org/grpc"

	"sanzi.io/muid/internal/profile/core"
	"sanzi.io/muid/internal/profile/ent"
	"sanzi.io/muid/pkg/authzclient"
	"sanzi.io/muid/pkg/shared/pubsub"
)

const ConfigEnvPrefix = "PROFILE"

type Config struct {
	Debug bool `envconfig:"DEBUG" default:"false"`

	Port        int    `envconfig:"PORT"         default:"5324"`
	DatabaseURL string `envconfig:"DATABASE_URL"                required:"true"`
	NATSURL     string `envconfig:"NATS_URL"                    required:"true"`

	RequestTimeoutSeconds int `envconfig:"REQUEST_TIMEOUT_SECONDS" default:"10"`

	// AuthzInternalGRPCAddr is the authz internal listener (AuthzService),
	// used by the local enforcer to authorize organization-profile edits.
	// Empty disables UpdateOrganizationProfile (returns Unavailable).
	AuthzInternalGRPCAddr string `envconfig:"AUTHZ_INTERNAL_GRPC_ADDR"`
	// AuthzRoleCacheTTLSeconds bounds how long resolved user roles are reused.
	AuthzRoleCacheTTLSeconds int `envconfig:"AUTHZ_ROLE_CACHE_TTL_SECONDS" default:"300"`
	// AuthzPolicyRefreshSeconds is the periodic namespace-policy resync.
	AuthzPolicyRefreshSeconds int `envconfig:"AUTHZ_POLICY_REFRESH_SECONDS" default:"300"`

	// PublicAssetURL is the CDN or public origin for objects in the production assets bucket (used when deriving URLs from UserAvatar.object_key).
	PublicAssetURL string `envconfig:"PUBLIC_ASSETS_URL" default:""`

	// R2 (S3 API). Leave AccountID empty to disable Start/Complete avatar RPCs.
	R2AccountID       string `envconfig:"R2_ACCOUNT_ID"        default:""`
	R2AccessKeyID     string `envconfig:"R2_ACCESS_KEY_ID"     default:""`
	R2SecretAccessKey string `envconfig:"R2_SECRET_ACCESS_KEY" default:""`
	// R2UploadBucket receives presigned client uploads (temporary staging).
	R2UploadBucket string `envconfig:"R2_UPLOAD_BUCKET"     default:""`
	// R2AssetsBucket stores processed WebP avatars served via PublicAssetURL.
	R2AssetsBucket string `envconfig:"R2_ASSETS_BUCKET"     default:""`

	GRPCTLSCertPath      string `envconfig:"GRPC_TLS_CERT_PATH"`
	GRPCTLSKeyPath       string `envconfig:"GRPC_TLS_KEY_PATH"`
	GRPCMTLSClientCAPath string `envconfig:"GRPC_MTLS_CLIENT_CA_PATH"`

	GRPCClientCertPath string `envconfig:"GRPC_CLIENT_CERT_PATH"`
	GRPCClientKeyPath  string `envconfig:"GRPC_CLIENT_KEY_PATH"`
	GRPCRootCAPath     string `envconfig:"GRPC_ROOT_CA_PATH"`
}

type InfraDependencies struct {
	GlobalConfig Config

	PubSub pubsub.PubSub
	Ent    *ent.Client
	// Avatars is optional; when nil, StartAvatarUpload / CompleteAvatarUpload return FailedPrecondition.
	Avatars *core.AvatarMedia

	// AuthzEnforcer authorizes organization-profile edits; nil when
	// AuthzInternalGRPCAddr is unset.
	AuthzEnforcer *authzclient.Enforcer
	authzConn     *grpc.ClientConn
}

func (d *InfraDependencies) Close() error {
	var errs []error
	if d.AuthzEnforcer != nil {
		if err := d.AuthzEnforcer.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if d.authzConn != nil {
		if err := d.authzConn.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if d.Ent != nil {
		err := d.Ent.Close()
		if err != nil {
			errs = append(errs, err)
		}
	}
	if d.PubSub != nil {
		if c, ok := d.PubSub.(io.Closer); ok {
			err := c.Close()
			if err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}
