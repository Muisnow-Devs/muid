package turnstile_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"sanzi.io/muid/infra/turnstile"
)

func TestVerifySuccess(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		if r.FormValue("secret") != "sek" || r.FormValue("response") != "tok" {
			t.Errorf("unexpected form: %v", r.Form)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"hostname":"example.com","challenge_ts":"2026-01-01T00:00:00Z"}`))
	}))
	defer srv.Close()

	v, err := turnstile.New(turnstile.Config{SecretKey: "sek", Endpoint: srv.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res, err := v.Verify(context.Background(), "tok", "1.2.3.4")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.Success || res.Hostname != "example.com" {
		t.Fatalf("unexpected result: %+v", res)
	}
}

func TestVerifyFailure(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":false,"error-codes":["invalid-input-response"]}`))
	}))
	defer srv.Close()

	v, err := turnstile.New(turnstile.Config{SecretKey: "sek", Endpoint: srv.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res, err := v.Verify(context.Background(), "tok", "")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Success {
		t.Fatal("expected failure result")
	}
	if len(res.ErrorCodes) != 1 || res.ErrorCodes[0] != "invalid-input-response" {
		t.Fatalf("error codes = %v", res.ErrorCodes)
	}
}

func TestVerifyMissingToken(t *testing.T) {
	t.Parallel()

	v, err := turnstile.New(turnstile.Config{SecretKey: "sek"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := v.Verify(context.Background(), "", ""); !errors.Is(err, turnstile.ErrMissingToken) {
		t.Fatalf("expected ErrMissingToken, got %v", err)
	}
}

func TestNewRequiresSecret(t *testing.T) {
	t.Parallel()

	if _, err := turnstile.New(turnstile.Config{}); !errors.Is(err, turnstile.ErrMissingSecret) {
		t.Fatalf("expected ErrMissingSecret, got %v", err)
	}
}

func TestUnexpectedStatus(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	v, err := turnstile.New(turnstile.Config{SecretKey: "sek", Endpoint: srv.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := v.Verify(context.Background(), "tok", ""); !errors.Is(err, turnstile.ErrUnexpectedStatus) {
		t.Fatalf("expected ErrUnexpectedStatus, got %v", err)
	}
}
