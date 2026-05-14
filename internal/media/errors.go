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

	// ErrRasterSignatureInvalid means the byte prefix is not a known JPEG/PNG/GIF/WebP signature.
	ErrRasterSignatureInvalid = errors.New("media: raster signature invalid")

	// ErrRasterHeadContentTypeMismatch means HEAD Content-Type (when a known raster MIME)
	// disagrees with magic-byte sniffing.
	ErrRasterHeadContentTypeMismatch = errors.New("media: raster head content-type mismatch")

	// ErrRasterSniffContentTypeConflict means http.DetectContentType on a bounded prefix
	// disagrees with magic-byte classification (e.g. executable or wrong image family).
	ErrRasterSniffContentTypeConflict = errors.New("media: raster sniff content-type conflict")

	// ErrRasterBodySizeMismatchHEAD means downloaded bytes length differs from HEAD size.
	ErrRasterBodySizeMismatchHEAD = errors.New("media: raster body size mismatch head")

	// ErrAvatarClientSizeDisagreesWithHEAD means the client-reported size disagrees with HEAD.
	ErrAvatarClientSizeDisagreesWithHEAD = errors.New("media: avatar client size disagrees with head")

	// ErrRasterObjectTooLarge is returned when HEAD or body exceeds [MaxAvatarStagingBytes].
	ErrRasterObjectTooLarge = errors.New("media: raster object too large")

	// ErrRasterHeadSizeInvalid means HEAD reported a non-positive content length.
	ErrRasterHeadSizeInvalid = errors.New("media: raster head size invalid")

	// ErrRasterDimensionsExceedLimit is returned when image.Config width/height or
	// total pixels exceed [MaxRasterDimension] / [MaxRasterPixelCount].
	ErrRasterDimensionsExceedLimit = errors.New("media: raster dimensions exceed limit")

	// ErrRasterClaimedKindMismatch means the declared MIME does not match magic-byte kind.
	ErrRasterClaimedKindMismatch = errors.New("media: raster claimed content-type does not match payload")
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
