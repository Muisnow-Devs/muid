package app

import "sanzi.io/muid/infra/r2"

// AvatarMedia connects a shared [r2.ObjectStore] to R2 upload (staging) and asset (production) buckets.
type AvatarMedia struct {
	Store          r2.ObjectStore
	UploadBucket   string
	AssetsBucket   string
	PublicAssetURL string
}

func (a *AvatarMedia) publicProdURL(objectKey string) string {
	return r2.PublicObjectURL(a.PublicAssetURL, objectKey)
}
