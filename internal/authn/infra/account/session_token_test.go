package account

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func validWireToken(t *testing.T) string {
	t.Helper()
	sel := make([]byte, SelectorLength)
	val := make([]byte, ValidatorLength)
	if _, err := rand.Read(sel); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(val); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(sel) + "." +
		base64.RawURLEncoding.EncodeToString(val)
}

func TestParseSessionToken(t *testing.T) {
	t.Parallel()

	wire := validWireToken(t)
	sel, val, err := ParseSessionToken(wire)
	if err != nil {
		t.Fatal(err)
	}
	if len(sel) != SelectorB64Length || len(val) != ValidatorB64Length {
		t.Fatalf("segment lengths: %d %d", len(sel), len(val))
	}
	if len(wire) != SessionTokenLength {
		t.Fatalf("wire length: got %d want %d", len(wire), SessionTokenLength)
	}
}

func TestParseSessionToken_rejectsInvalidWire(t *testing.T) {
	t.Parallel()

	valid := validWireToken(t)
	validSel, validVal, err := ParseSessionToken(valid)
	if err != nil {
		t.Fatal(err)
	}

	longSegment := strings.Repeat("A", SelectorB64Length+10)

	tests := []struct {
		name    string
		wire    string
		wantErr error
	}{
		{name: "empty", wire: "", wantErr: errInvalidSessionToken},
		{name: "whitespace only", wire: "   \t\n", wantErr: errInvalidSessionToken},
		{name: "single segment", wire: "bad", wantErr: errInvalidSessionToken},
		{name: "three segments", wire: "a.b.c", wantErr: errInvalidSessionToken},
		{name: "empty segments", wire: ".", wantErr: errInvalidSessionToken},
		{name: "selector too short", wire: "abc." + validVal, wantErr: errInvalidSessionToken},
		{name: "validator too short", wire: validSel + ".abc", wantErr: errInvalidSessionToken},
		{
			name:    "selector too long",
			wire:    longSegment + "." + validVal,
			wantErr: errInvalidSessionToken,
		},
		{
			name:    "invalid base64 in selector",
			wire:    strings.Repeat("!", SelectorB64Length) + "." + validVal,
			wantErr: errInvalidSessionToken,
		},
		{
			name:    "invalid base64 in validator",
			wire:    validSel + "." + strings.Repeat("?", ValidatorB64Length),
			wantErr: errInvalidSessionToken,
		},
		{
			name:    "oversize wire",
			wire:    valid + strings.Repeat("A", 256),
			wantErr: errInvalidSessionToken,
		},
		{
			name:    "extra dot suffix",
			wire:    valid + ".extra",
			wantErr: errInvalidSessionToken,
		},
		{
			name:    "embedded newline",
			wire:    validSel + "\n." + validVal,
			wantErr: errInvalidSessionToken,
		},
		{
			name:    "null byte in selector segment",
			wire:    validSel[:1] + "\x00" + validSel[2:] + "." + validVal,
			wantErr: errInvalidSessionToken,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, _, err := ParseSessionToken(tc.wire)
			if err == nil {
				t.Fatal("expected error")
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("got %v want %v", err, tc.wantErr)
			}
		})
	}
}

func TestParseSessionToken_trimsSurroundingSpace(t *testing.T) {
	t.Parallel()

	wire := validWireToken(t)
	_, _, err := ParseSessionToken("  " + wire + "  ")
	if err != nil {
		t.Fatalf("trimmed valid token: %v", err)
	}
}

func TestDecodeSelectorAndValidator_rejectWrongDecodedLength(t *testing.T) {
	t.Parallel()

	// 15-byte selector encodes to 20 chars, not SelectorB64Length (22).
	shortSel := make([]byte, SelectorLength-1)
	if _, err := rand.Read(shortSel); err != nil {
		t.Fatal(err)
	}
	shortSelB64 := base64.RawURLEncoding.EncodeToString(shortSel)

	_, err := decodeSelector(shortSelB64)
	if err == nil || !errors.Is(err, errInvalidSessionToken) {
		t.Fatalf("short selector decode: got %v", err)
	}

	shortVal := make([]byte, ValidatorLength-1)
	if _, err := rand.Read(shortVal); err != nil {
		t.Fatal(err)
	}
	shortValB64 := base64.RawURLEncoding.EncodeToString(shortVal)

	_, err = decodeValidatorSecret(shortValB64)
	if err == nil || !errors.Is(err, errInvalidSessionToken) {
		t.Fatalf("short validator decode: got %v", err)
	}
}
