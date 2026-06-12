package core

import "sanzi.io/muid/infra/r2"

// AvatarMedia connects a shared [r2.ObjectStore] to R2 upload (staging) and asset (production) buckets.
type AvatarMedia struct {
	Store          r2.ObjectStore
	UploadBucket   string
	AssetsBucket   string
	PublicAssetURL string
}

// PublicProdURL derives the public CDN URL for an object in the assets bucket.
// This is the single source of that rule; do not duplicate it elsewhere.
func (a *AvatarMedia) PublicProdURL(objectKey string) string {
	return r2.PublicObjectURL(a.PublicAssetURL, objectKey)
}
