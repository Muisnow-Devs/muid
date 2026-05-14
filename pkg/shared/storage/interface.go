package storage

import (
	"context"
	"io"
	"time"
)

// ObjectHead is object metadata returned from HeadObject / GetObject.
type ObjectHead struct {
	Size        int64
	ContentType string
}

// ObjectStore is a minimal S3-compatible object API (Cloudflare R2, AWS S3, etc.).
// Callers pass the bucket name per operation so one client can access staging and production buckets.
type ObjectStore interface {
	PresignPut(ctx context.Context, bucket, objectKey, contentType string, exp time.Duration) (url string, expires time.Time, err error)
	HeadObject(ctx context.Context, bucket, objectKey string) (ObjectHead, error)
	GetObject(ctx context.Context, bucket, objectKey string) (io.ReadCloser, ObjectHead, error)
	PutObject(ctx context.Context, bucket, objectKey string, body []byte, contentType string) error
	DeleteObject(ctx context.Context, bucket, objectKey string) error
}
