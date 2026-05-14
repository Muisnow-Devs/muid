package r2

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	smhttp "github.com/aws/smithy-go/transport/http"

	"sanzi.io/muid/pkg/shared/storage"
)

// R2ObjectStore uses the Cloudflare R2 S3-compatible API (any single-account endpoint).
type R2ObjectStore struct {
	apiClient *s3.Client
	presign   *s3.PresignClient
}

// NewR2ObjectStore builds an S3 client targeting https://<accountID>.r2.cloudflarestorage.com.
func NewR2ObjectStore(ctx context.Context, accountID, accessKeyID, secretAccessKey string) (ObjectStore, error) {
	endpoint := fmt.Sprintf("https://%s.r2.cloudflarestorage.com", accountID)

	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKeyID, secretAccessKey, "")),
		config.WithRegion("auto"),
	)
	if err != nil {
		return nil, err
	}

	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(endpoint)
		o.UsePathStyle = true
	})

	return &R2ObjectStore{
		apiClient: client,
		presign:   s3.NewPresignClient(client),
	}, nil
}

func mapS3NotFound(err error) error {
	if err == nil {
		return nil
	}
	var re *smhttp.ResponseError
	if errors.As(err, &re) && re.HTTPStatusCode() == 404 {
		return storage.ErrObjectNotFound
	}
	return err
}

func (r *R2ObjectStore) PresignPut(ctx context.Context, bucket, objectKey, contentType string, exp time.Duration) (string, time.Time, error) {
	out, err := r.presign.PresignPutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(bucket),
		Key:         aws.String(objectKey),
		ContentType: aws.String(contentType),
	}, s3.WithPresignExpires(exp))
	if err != nil {
		return "", time.Time{}, mapS3NotFound(err)
	}
	return out.URL, time.Now().Add(exp), nil
}

func (r *R2ObjectStore) HeadObject(ctx context.Context, bucket, objectKey string) (ObjectHead, error) {
	out, err := r.apiClient.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(objectKey),
	})
	if err != nil {
		return ObjectHead{}, mapS3NotFound(err)
	}
	var h ObjectHead
	if out.ContentLength != nil {
		h.Size = *out.ContentLength
	}
	if out.ContentType != nil {
		h.ContentType = strings.TrimSpace(*out.ContentType)
	}
	return h, nil
}

func (r *R2ObjectStore) GetObject(ctx context.Context, bucket, objectKey string) (io.ReadCloser, ObjectHead, error) {
	out, err := r.apiClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(objectKey),
	})
	if err != nil {
		return nil, ObjectHead{}, mapS3NotFound(err)
	}
	var h ObjectHead
	if out.ContentLength != nil {
		h.Size = *out.ContentLength
	}
	if out.ContentType != nil {
		h.ContentType = strings.TrimSpace(*out.ContentType)
	}
	return out.Body, h, nil
}

func (r *R2ObjectStore) PutObject(ctx context.Context, bucket, objectKey string, body []byte, contentType string) error {
	_, err := r.apiClient.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(bucket),
		Key:         aws.String(objectKey),
		Body:        bytes.NewReader(body),
		ContentType: aws.String(contentType),
	})
	return err
}

func (r *R2ObjectStore) DeleteObject(ctx context.Context, bucket, objectKey string) error {
	_, err := r.apiClient.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(objectKey),
	})
	return err
}
