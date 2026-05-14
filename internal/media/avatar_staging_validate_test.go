package media

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"testing"
)

func writePNGChunk(buf *bytes.Buffer, typ string, data []byte) {
	_ = binary.Write(buf, binary.BigEndian, uint32(len(data)))
	buf.WriteString(typ)
	buf.Write(data)
	crc := crc32.ChecksumIEEE(append([]byte(typ), data...))
	_ = binary.Write(buf, binary.BigEndian, crc)
}

// minimalPNGWithIHDR returns a syntactically valid PNG with the given IHDR dimensions
// (no pixel data; png.DecodeConfig only needs IHDR).
func minimalPNGWithIHDR(width, height uint32) []byte {
	var buf bytes.Buffer
	buf.Write([]byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'})
	ihdr := make([]byte, 13)
	binary.BigEndian.PutUint32(ihdr[0:4], width)
	binary.BigEndian.PutUint32(ihdr[4:8], height)
	ihdr[8] = 8
	ihdr[9] = 2
	writePNGChunk(&buf, "IHDR", ihdr)
	writePNGChunk(&buf, "IEND", nil)
	return buf.Bytes()
}

const tinyPNGB64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="

func TestSniffRasterKind(t *testing.T) {
	t.Parallel()
	rawPNG, err := base64.StdEncoding.DecodeString(tinyPNGB64)
	if err != nil {
		t.Fatal(err)
	}
	if got := SniffRasterKind(rawPNG); got != RasterPNG {
		t.Fatalf("PNG: got %v want RasterPNG", got)
	}
	if SniffRasterKind([]byte("MZ\x90\x00")) != RasterUnknown {
		t.Fatal("expected unknown for executable prefix")
	}
	if SniffRasterKind([]byte{0xff, 0xd8, 0xff, 0xe0}) != RasterJPEG {
		t.Fatal("expected JPEG")
	}
	if SniffRasterKind([]byte("GIF89a\x01\x00\x01\x00")) != RasterGIF {
		t.Fatal("expected GIF")
	}
}

func TestValidateAvatarStagingObject_dimensionReject(t *testing.T) {
	t.Parallel()
	w := uint32(MaxRasterDimension + 1)
	raw := minimalPNGWithIHDR(w, 1)
	tr := AvatarStagingTrust{
		HeadContentLength: int64(len(raw)),
		HeadContentType:   "image/png",
		ClientByteSize:    int64(len(raw)),
	}
	_, err := ValidateAvatarStagingObject(raw, tr)
	if !errors.Is(err, ErrRasterDimensionsExceedLimit) {
		t.Fatalf("expected ErrRasterDimensionsExceedLimit, got %v", err)
	}
}

func TestValidateAvatarStagingObject_pixelBudgetReject(t *testing.T) {
	t.Parallel()
	// 6000*6000 > MaxRasterPixelCount (32e6)
	raw := minimalPNGWithIHDR(6000, 6000)
	tr := AvatarStagingTrust{
		HeadContentLength: int64(len(raw)),
		HeadContentType:   "image/png",
		ClientByteSize:    int64(len(raw)),
	}
	_, err := ValidateAvatarStagingObject(raw, tr)
	if !errors.Is(err, ErrRasterDimensionsExceedLimit) {
		t.Fatalf("expected ErrRasterDimensionsExceedLimit, got %v", err)
	}
}

func TestValidateAvatarStagingObject_headMIMEConflict(t *testing.T) {
	t.Parallel()
	raw, err := base64.StdEncoding.DecodeString(tinyPNGB64)
	if err != nil {
		t.Fatal(err)
	}
	tr := AvatarStagingTrust{
		HeadContentLength: int64(len(raw)),
		HeadContentType:   "image/jpeg",
		ClientByteSize:    int64(len(raw)),
	}
	_, err = ValidateAvatarStagingObject(raw, tr)
	if !errors.Is(err, ErrRasterHeadContentTypeMismatch) {
		t.Fatalf("expected ErrRasterHeadContentTypeMismatch, got %v", err)
	}
}

func TestValidateAvatarStagingObject_clientSizeDisagrees(t *testing.T) {
	t.Parallel()
	raw, err := base64.StdEncoding.DecodeString(tinyPNGB64)
	if err != nil {
		t.Fatal(err)
	}
	tr := AvatarStagingTrust{
		HeadContentLength: int64(len(raw)),
		HeadContentType:   "image/png",
		ClientByteSize:    int64(len(raw) - 1),
	}
	_, err = ValidateAvatarStagingObject(raw, tr)
	if !errors.Is(err, ErrAvatarClientSizeDisagreesWithHEAD) {
		t.Fatalf("expected ErrAvatarClientSizeDisagreesWithHEAD, got %v", err)
	}
}

func TestValidateRasterProcessInput_claimedMismatch(t *testing.T) {
	t.Parallel()
	raw, err := base64.StdEncoding.DecodeString(tinyPNGB64)
	if err != nil {
		t.Fatal(err)
	}
	err = validateRasterProcessInput(raw, "image/jpeg")
	if !errors.Is(err, ErrRasterClaimedKindMismatch) {
		t.Fatalf("expected ErrRasterClaimedKindMismatch, got %v", err)
	}
}
