package config

import (
	"reflect"
	"testing"
)

func TestPasskeyOriginsDecodeJSON(t *testing.T) {
	t.Parallel()

	var origins PasskeyOrigins
	err := origins.Decode(`[" https://app.example.test ", "", "http://localhost:3000"]`)
	if err != nil {
		t.Fatalf("PasskeyOrigins.Decode() error = %v", err)
	}

	got := []string(origins)
	want := []string{"https://app.example.test", "http://localhost:3000"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("PasskeyOrigins.Decode() = %+v, want %+v", got, want)
	}
}

func TestPasskeyOriginsDecodeCommaSeparated(t *testing.T) {
	t.Parallel()

	var origins PasskeyOrigins
	err := origins.Decode(" https://app.example.test, ,http://localhost:3000 ")
	if err != nil {
		t.Fatalf("PasskeyOrigins.Decode() error = %v", err)
	}

	got := []string(origins)
	want := []string{"https://app.example.test", "http://localhost:3000"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("PasskeyOrigins.Decode() = %+v, want %+v", got, want)
	}
}

func TestParsePasskeyConfigTrimsRelyingPartyFields(t *testing.T) {
	t.Parallel()

	got := ParsePasskeyConfig(
		" app.example.test ",
		" muid auth ",
		PasskeyOrigins{"https://app.example.test"},
	)

	if got.RPID != "app.example.test" {
		t.Fatalf("RPID = %q, want app.example.test", got.RPID)
	}
	if got.RPDisplayName != "muid auth" {
		t.Fatalf("RPDisplayName = %q, want muid auth", got.RPDisplayName)
	}
	if !reflect.DeepEqual(got.RPOrigins, []string{"https://app.example.test"}) {
		t.Fatalf("RPOrigins = %+v, want configured origin", got.RPOrigins)
	}
}
