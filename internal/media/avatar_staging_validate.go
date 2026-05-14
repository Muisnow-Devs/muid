package media

import (
	"bytes"
	"errors"
	"image"
	"image/gif"
	"image/jpeg"
	"image/png"

	xwebp "golang.org/x/image/webp"
)

// AvatarStagingTrust carries server-side object metadata for staging avatars.
// HeadContentLength must come from object store HEAD (or equivalent).
type AvatarStagingTrust struct {
	HeadContentLength int64
	HeadContentType   string
	// ClientByteSize is the optional client-reported size; if non-zero it must
	// equal HeadContentLength (HEAD is authoritative).
	ClientByteSize int64
}

// ValidateAvatarStagingObject enforces trusted size, magic-byte sniffing,
// optional HEAD Content-Type cross-check, bounded-prefix DetectContentType
// corroboration, and image.DecodeConfig dimension caps before full decode.
func ValidateAvatarStagingObject(
	raw []byte,
	tr AvatarStagingTrust,
) (canonicalMIME string, err error) {
	if len(raw) == 0 {
		return "", ErrEmptyRasterInput
	}
	if tr.HeadContentLength <= 0 {
		return "", ErrRasterHeadSizeInvalid
	}
	if tr.HeadContentLength > MaxAvatarStagingBytes {
		return "", ErrRasterObjectTooLarge
	}
	if int64(len(raw)) != tr.HeadContentLength {
		return "", ErrRasterBodySizeMismatchHEAD
	}
	if tr.ClientByteSize != 0 && tr.ClientByteSize != tr.HeadContentLength {
		return "", ErrAvatarClientSizeDisagreesWithHEAD
	}

	kind := SniffRasterKind(raw)
	if kind == RasterUnknown {
		return "", ErrRasterSignatureInvalid
	}
	if detectContentTypeDisagreesWithKind(raw, kind) {
		return "", ErrRasterSniffContentTypeConflict
	}

	canonicalMIME = rasterKindMIME(kind)
	headNorm := normalizeMIME(tr.HeadContentType)
	if headNorm != "" && AllowedRasterContentType(headNorm) && headNorm != canonicalMIME {
		return "", ErrRasterHeadContentTypeMismatch
	}

	cfg, err := rasterDecodeConfig(kind, raw)
	if err != nil {
		return "", errors.Join(ErrRasterDecodeFailed, err)
	}
	if err := checkRasterConfigLimits(cfg); err != nil {
		return "", err
	}

	return canonicalMIME, nil
}

func rasterDecodeConfig(kind RasterKind, raw []byte) (image.Config, error) {
	r := bytes.NewReader(raw)
	switch kind {
	case RasterJPEG:
		return jpeg.DecodeConfig(r)
	case RasterPNG:
		return png.DecodeConfig(r)
	case RasterGIF:
		return gif.DecodeConfig(r)
	case RasterWebP:
		return xwebp.DecodeConfig(r)
	default:
		return image.Config{}, ErrRasterSignatureInvalid
	}
}

func checkRasterConfigLimits(cfg image.Config) error {
	if cfg.Width <= 0 || cfg.Height <= 0 {
		return ErrRasterDimensionsExceedLimit
	}
	if cfg.Width > MaxRasterDimension || cfg.Height > MaxRasterDimension {
		return ErrRasterDimensionsExceedLimit
	}
	pix := int64(cfg.Width) * int64(cfg.Height)
	if pix > int64(MaxRasterPixelCount) {
		return ErrRasterDimensionsExceedLimit
	}
	return nil
}
