package media

import (
	"bytes"
	"fmt"
	"image"
	"image/draw"
	"strings"

	webp "github.com/skrashevich/go-webp"
	xdraw "golang.org/x/image/draw"

	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
)

// avatarOutputPixels is the max width/height of the square WebP stored on the CDN.
const avatarOutputPixels = 512

// WebPRasterAvatarProcessor is the default [RasterAvatarProcessor] implementation.
type WebPRasterAvatarProcessor struct{}

// NewWebPRasterAvatarProcessor returns a lossy WebP pipeline suitable for avatars.
func NewWebPRasterAvatarProcessor() RasterAvatarProcessor {
	return &WebPRasterAvatarProcessor{}
}

// ProcessToSquareWebP decodes a raster image, center-crops to a square, scales to
// avatarOutputPixels, and encodes lossy WebP.
func (p *WebPRasterAvatarProcessor) ProcessToSquareWebP(raw []byte, contentType string) ([]byte, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("empty image")
	}
	if !AllowedRasterContentType(contentType) {
		return nil, fmt.Errorf("unsupported content type %q", contentType)
	}
	img, _, err := image.Decode(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("decode image: %w", err)
	}
	sq := squareCenterCropNRGBA(img)
	scaled := scaleToSquareMax(sq, avatarOutputPixels)
	var buf bytes.Buffer
	if err := webp.Encode(&buf, scaled, &webp.Options{Lossy: true, Quality: 82}); err != nil {
		return nil, fmt.Errorf("encode webp: %w", err)
	}
	return buf.Bytes(), nil
}

// AllowedRasterContentType reports whether ct is a supported raster image MIME type
// (before object download / processing).
func AllowedRasterContentType(ct string) bool {
	ct = strings.ToLower(strings.TrimSpace(strings.Split(ct, ";")[0]))
	switch ct {
	case "image/jpeg", "image/png", "image/gif", "image/webp":
		return true
	default:
		return false
	}
}

func squareCenterCropNRGBA(src image.Image) *image.NRGBA {
	b := src.Bounds()
	w, h := b.Dx(), b.Dy()
	if w <= 0 || h <= 0 {
		return image.NewNRGBA(image.Rect(0, 0, 1, 1))
	}
	side := w
	if h < side {
		side = h
	}
	x0 := b.Min.X + (w-side)/2
	y0 := b.Min.Y + (h-side)/2
	dstR := image.Rect(0, 0, side, side)
	dst := image.NewNRGBA(dstR)
	sp := image.Pt(x0, y0)
	draw.Draw(dst, dstR, src, sp, draw.Src)
	return dst
}

func scaleToSquareMax(src *image.NRGBA, max int) *image.NRGBA {
	b := src.Bounds()
	side := b.Dx()
	if side <= max {
		return src
	}
	dstR := image.Rect(0, 0, max, max)
	dst := image.NewNRGBA(dstR)
	xdraw.CatmullRom.Scale(dst, dstR, src, b, draw.Over, nil)
	return dst
}
