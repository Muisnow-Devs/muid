// Package synthavatar renders deterministic placeholder avatars (goavatar) keyed by profile user id.
package synthavatar

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image/png"

	"github.com/MuhammadSaim/goavatar"
	"github.com/google/uuid"
)

// Seed is the string passed to goavatar.Make for this user; stable for the lifetime of the profile id.
func Seed(userID uuid.UUID) string {
	return userID.String()
}

// PNGBytes returns a PNG raster suitable for validation and RasterAvatarProcessor ingestion.
func PNGBytes(userID uuid.UUID) ([]byte, error) {
	img := goavatar.Make(Seed(userID), goavatar.WithSize(256))
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// PNGBytesDisplay returns a smaller PNG for inline data URLs (same pattern as PNGBytes, lower resolution).
func PNGBytesDisplay(userID uuid.UUID) ([]byte, error) {
	img := goavatar.Make(Seed(userID))
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// DataURL returns a PNG data URL for API display fallback when no stored CDN avatar applies.
func DataURL(userID uuid.UUID) (string, error) {
	raw, err := PNGBytesDisplay(userID)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("data:image/png;base64,%s", base64.StdEncoding.EncodeToString(raw)), nil
}
