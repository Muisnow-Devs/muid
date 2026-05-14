package media

import "errors"

var (
	// ErrEmptyRasterInput is returned when image bytes are empty.
	ErrEmptyRasterInput = errors.New("media: empty raster input")

	// ErrUnsupportedRasterContentType is returned for non-raster or unknown MIME types.
	ErrUnsupportedRasterContentType = errors.New("media: unsupported raster content type")

	// ErrRasterDecodeFailed is returned when bytes cannot be decoded as a supported raster image.
	ErrRasterDecodeFailed = errors.New("media: raster decode failed")

	// ErrWebPEncodeFailed wraps the underlying encoder error for WebP output.
	ErrWebPEncodeFailed = errors.New("media: encode webp failed")
)

// UnsupportedRasterContentTypeError attaches the caller-supplied Content-Type for diagnostics.
type UnsupportedRasterContentTypeError struct {
	ContentType string
}

func (e *UnsupportedRasterContentTypeError) Error() string {
	return "media: unsupported raster content type: " + e.ContentType
}

func (e *UnsupportedRasterContentTypeError) Unwrap() error {
	return ErrUnsupportedRasterContentType
}

// Detail implements [DetailError]; safe to log (MIME type only).
func (e *UnsupportedRasterContentTypeError) Detail() string { return e.ContentType }

// DetailError carries a short, non-sensitive explanation for expected media failures.
type DetailError interface {
	error
	Detail() string
}
