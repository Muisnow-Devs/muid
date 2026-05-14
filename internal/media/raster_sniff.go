package media

import (
	"net/http"
	"strings"
)

// RasterKind identifies an image container detected from magic bytes.
type RasterKind int

const (
	RasterUnknown RasterKind = iota
	RasterJPEG
	RasterPNG
	RasterGIF
	RasterWebP
)

// MIME for each [RasterKind] (lowercase, no parameters).
func rasterKindMIME(k RasterKind) string {
	switch k {
	case RasterJPEG:
		return "image/jpeg"
	case RasterPNG:
		return "image/png"
	case RasterGIF:
		return "image/gif"
	case RasterWebP:
		return ContentTypeWebP
	default:
		return ""
	}
}

// SniffRasterKind inspects the leading bytes of b for a known raster signature.
// It does not decode image metadata.
func SniffRasterKind(b []byte) RasterKind {
	if len(b) < 3 {
		return RasterUnknown
	}
	// JPEG
	if b[0] == 0xff && b[1] == 0xd8 && b[2] == 0xff {
		return RasterJPEG
	}
	// PNG
	if len(b) >= 8 &&
		b[0] == 0x89 && b[1] == 'P' && b[2] == 'N' && b[3] == 'G' &&
		b[4] == '\r' && b[5] == '\n' && b[6] == 0x1a && b[7] == '\n' {
		return RasterPNG
	}
	// GIF87a / GIF89a
	if len(b) >= 6 {
		if b[0] == 'G' && b[1] == 'I' && b[2] == 'F' && b[3] == '8' &&
			(b[4] == '7' || b[4] == '9') && b[5] == 'a' {
			return RasterGIF
		}
	}
	// WebP: RIFF....WEBP
	if len(b) >= 12 &&
		b[0] == 'R' && b[1] == 'I' && b[2] == 'F' && b[3] == 'F' &&
		b[8] == 'W' && b[9] == 'E' && b[10] == 'B' && b[11] == 'P' {
		return RasterWebP
	}
	return RasterUnknown
}

// normalizeMIME strips parameters and lowercases the primary type/subtype.
func normalizeMIME(ct string) string {
	ct = strings.TrimSpace(strings.Split(ct, ";")[0])
	return strings.ToLower(ct)
}

// sniffPrefixBytes is how many leading bytes we pass to [http.DetectContentType]
// as a secondary check (never authoritative alone).
const sniffPrefixBytes = 512

// detectContentTypePrefix mirrors net/http sniffing on a bounded prefix.
func detectContentTypePrefix(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	n := sniffPrefixBytes
	if len(b) < n {
		n = len(b)
	}
	return http.DetectContentType(b[:n])
}

// detectContentTypeDisagreesWithKind returns true when the stdlib sniff result
// is a concrete image/* type that conflicts with magic-byte [RasterKind].
func detectContentTypeDisagreesWithKind(b []byte, k RasterKind) bool {
	dct := normalizeMIME(detectContentTypePrefix(b))
	if dct == "" || dct == "application/octet-stream" {
		return false
	}
	if !strings.HasPrefix(dct, "image/") {
		return true
	}
	want := rasterKindMIME(k)
	if want == "" {
		return true
	}
	return dct != want
}
