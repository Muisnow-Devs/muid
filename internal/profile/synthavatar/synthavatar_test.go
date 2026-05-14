package synthavatar

import (
	"bytes"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestSeed(t *testing.T) {
	t.Parallel()
	id := uuid.MustParse("018f1234-5678-7abc-8def-123456789abc")
	if got, want := Seed(id), id.String(); got != want {
		t.Fatalf("Seed = %q, want %q", got, want)
	}
}

func TestPNGBytesStable(t *testing.T) {
	t.Parallel()
	id := uuid.MustParse("018f1234-5678-7abc-8def-123456789abc")
	a, err := PNGBytes(id)
	if err != nil {
		t.Fatal(err)
	}
	b, err := PNGBytes(id)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("PNGBytes not stable for same id")
	}
	if len(a) < 100 || !bytes.HasPrefix(a, []byte{0x89, 0x50, 0x4e, 0x47}) {
		t.Fatalf("unexpected PNG header / size: len=%d", len(a))
	}
}

func TestDataURLPrefix(t *testing.T) {
	t.Parallel()
	id := uuid.MustParse("018f1234-5678-7abc-8def-123456789abc")
	u, err := DataURL(id)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(u, "data:image/png;base64,") {
		t.Fatalf("unexpected data url prefix: %q", u[:min(40, len(u))])
	}
}
