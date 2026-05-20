package session

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func validWireToken(t *testing.T) string {
	t.Helper()
	sel := make([]byte, SelectorByteLength)
	val := make([]byte, ValidatorByteLength)
	if _, err := rand.Read(sel); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(val); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(sel) + "." +
		base64.RawURLEncoding.EncodeToString(val)
}

func TestParseWireSessionToken(t *testing.T) {
	t.Parallel()

	wire := validWireToken(t)
	sel, val, err := ParseWireSessionToken(wire)
	if err != nil {
		t.Fatal(err)
	}
	if len(sel) != SelectorB64Length || len(val) != ValidatorB64Length {
		t.Fatalf("segment lengths: %d %d", len(sel), len(val))
	}
	if len(wire) != WireSessionTokenLength {
		t.Fatalf("wire length: got %d want %d", len(wire), WireSessionTokenLength)
	}
}

func TestParseWireSessionToken_rejectsInvalidWire(t *testing.T) {
	t.Parallel()

	valid := validWireToken(t)
	validSel, validVal, err := ParseWireSessionToken(valid)
	if err != nil {
		t.Fatal(err)
	}

	longSegment := strings.Repeat("A", SelectorB64Length+10)

	tests := []struct {
		name    string
		wire    string
		wantErr error
	}{
		{name: "empty", wire: "", wantErr: ErrInvalidWireSessionToken},
		{name: "whitespace only", wire: "   \t\n", wantErr: ErrInvalidWireSessionToken},
		{name: "single segment", wire: "bad", wantErr: ErrInvalidWireSessionToken},
		{name: "three segments", wire: "a.b.c", wantErr: ErrInvalidWireSessionToken},
		{name: "empty segments", wire: ".", wantErr: ErrInvalidWireSessionToken},
		{
			name:    "selector too short",
			wire:    "abc." + validVal,
			wantErr: ErrInvalidWireSessionToken,
		},
		{
			name:    "validator too short",
			wire:    validSel + ".abc",
			wantErr: ErrInvalidWireSessionToken,
		},
		{
			name:    "selector too long",
			wire:    longSegment + "." + validVal,
			wantErr: ErrInvalidWireSessionToken,
		},
		{
			name:    "invalid base64 in selector",
			wire:    strings.Repeat("!", SelectorB64Length) + "." + validVal,
			wantErr: ErrInvalidWireSessionToken,
		},
		{
			name:    "invalid base64 in validator",
			wire:    validSel + "." + strings.Repeat("?", ValidatorB64Length),
			wantErr: ErrInvalidWireSessionToken,
		},
		{
			name:    "oversize wire",
			wire:    valid + strings.Repeat("A", 256),
			wantErr: ErrInvalidWireSessionToken,
		},
		{
			name:    "extra dot suffix",
			wire:    valid + ".extra",
			wantErr: ErrInvalidWireSessionToken,
		},
		{
			name:    "embedded newline",
			wire:    validSel + "\n." + validVal,
			wantErr: ErrInvalidWireSessionToken,
		},
		{
			name:    "null byte in selector segment",
			wire:    validSel[:1] + "\x00" + validSel[2:] + "." + validVal,
			wantErr: ErrInvalidWireSessionToken,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, _, err := ParseWireSessionToken(tc.wire)
			if err == nil {
				t.Fatal("expected error")
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("got %v want %v", err, tc.wantErr)
			}
		})
	}
}

func TestParseWireSessionToken_trimsSurroundingSpace(t *testing.T) {
	t.Parallel()

	wire := validWireToken(t)
	_, _, err := ParseWireSessionToken("  " + wire + "  ")
	if err != nil {
		t.Fatalf("trimmed valid token: %v", err)
	}
}

func TestDecodeWireSelectorAndValidator_rejectWrongDecodedLength(t *testing.T) {
	t.Parallel()

	// 15-byte selector encodes to 20 chars, not SelectorB64Length (22).
	shortSel := make([]byte, SelectorByteLength-1)
	if _, err := rand.Read(shortSel); err != nil {
		t.Fatal(err)
	}
	shortSelB64 := base64.RawURLEncoding.EncodeToString(shortSel)

	_, err := DecodeWireSelectorBytes(shortSelB64)
	if err == nil || !errors.Is(err, ErrInvalidWireSessionToken) {
		t.Fatalf("short selector decode: got %v", err)
	}

	shortVal := make([]byte, ValidatorByteLength-1)
	if _, err := rand.Read(shortVal); err != nil {
		t.Fatal(err)
	}
	shortValB64 := base64.RawURLEncoding.EncodeToString(shortVal)

	_, err = DecodeWireValidatorSecret(shortValB64)
	if err == nil || !errors.Is(err, ErrInvalidWireSessionToken) {
		t.Fatalf("short validator decode: got %v", err)
	}
}
