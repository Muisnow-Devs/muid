package turnstile

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"sanzi.io/muid/pkg/errutil"
)

// DefaultEndpoint is Cloudflare's Turnstile siteverify URL.
const DefaultEndpoint = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

// Config configures the HTTP verifier.
type Config struct {
	// SecretKey is the Turnstile secret (required).
	SecretKey string
	// Endpoint overrides DefaultEndpoint (used by tests).
	Endpoint string
	// HTTPClient overrides the default client (with a 10s timeout).
	HTTPClient *http.Client
}

type httpVerifier struct {
	secret   string
	endpoint string
	client   *http.Client
}

// New builds an HTTP-backed Verifier.
func New(cfg Config) (Verifier, error) {
	if strings.TrimSpace(cfg.SecretKey) == "" {
		return nil, ErrMissingSecret
	}
	endpoint := strings.TrimSpace(cfg.Endpoint)
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &httpVerifier{secret: cfg.SecretKey, endpoint: endpoint, client: client}, nil
}

type verifyResponse struct {
	Success     bool     `json:"success"`
	ErrorCodes  []string `json:"error-codes"`
	ChallengeTS string   `json:"challenge_ts"`
	Hostname    string   `json:"hostname"`
	Action      string   `json:"action"`
}

// Verify posts the token to the siteverify endpoint and returns the result.
func (v *httpVerifier) Verify(ctx context.Context, token, remoteIP string) (Result, error) {
	if strings.TrimSpace(token) == "" {
		return Result{}, ErrMissingToken
	}

	form := url.Values{}
	form.Set("secret", v.secret)
	form.Set("response", token)
	if ip := strings.TrimSpace(remoteIP); ip != "" {
		form.Set("remoteip", ip)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := v.client.Do(req)
	if err != nil {
		return Result{}, err
	}
	defer errutil.Close(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return Result{}, fmt.Errorf("%w: %d", ErrUnexpectedStatus, resp.StatusCode)
	}

	var decoded verifyResponse
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return Result{}, err
	}

	return Result{
		Success:     decoded.Success,
		ErrorCodes:  decoded.ErrorCodes,
		ChallengeTS: decoded.ChallengeTS,
		Hostname:    decoded.Hostname,
		Action:      decoded.Action,
	}, nil
}
