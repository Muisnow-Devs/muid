package media

import (
	"bytes"
	"encoding/base64"
	"testing"
)

// 1×1 red PNG (base64).
const tinyPNG = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="

func TestWebPRasterAvatarProcessor_ProcessToSquareWebP(t *testing.T) {
	raw, err := base64.StdEncoding.DecodeString(tinyPNG)
	if err != nil {
		t.Fatal(err)
	}
	p := NewWebPRasterAvatarProcessor()
	out, err := p.ProcessToSquareWebP(raw, "image/png")
	if err != nil {
		t.Fatal(err)
	}
	if len(out) < 32 {
		t.Fatalf("webp too small: %d", len(out))
	}
	if !bytes.HasPrefix(out, []byte("RIFF")) {
		t.Fatalf("expected WebP/RIFF prefix, got %q", out[:min(8, len(out))])
	}
}
