package app

import (
	"errors"
	"io"

	"sanzi.io/muid/internal/profile/ent"
	profilegrpc "sanzi.io/muid/internal/profile/grpc"
	"sanzi.io/muid/pkg/shared/pubsub"
)

const ConfigEnvPrefix = "PROFILE"

type Config struct {
	Debug bool `envconfig:"DEBUG" default:"false"`

	Port        int    `envconfig:"PORT"         default:"5324"`
	DatabaseURL string `envconfig:"DATABASE_URL"                required:"true"`
	NATSURL     string `envconfig:"NATS_URL"                    required:"true"`

	RequestTimeoutSeconds int `envconfig:"REQUEST_TIMEOUT_SECONDS" default:"10"`

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
}

type InfraDependencies struct {
	GlobalConfig Config

	PubSub pubsub.PubSub
	Ent    *ent.Client
	// Avatars is optional; when nil, StartAvatarUpload / CompleteAvatarUpload return FailedPrecondition.
	Avatars *profilegrpc.AvatarMedia
}

func (d *InfraDependencies) Close() error {
	var errs []error
	if d.Ent != nil {
		if err := d.Ent.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if d.PubSub != nil {
		if c, ok := d.PubSub.(io.Closer); ok {
			if err := c.Close(); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}
