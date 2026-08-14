package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sanzi.io/muid/infra/geoip"
	"sanzi.io/muid/infra/mocked"
	"sanzi.io/muid/infra/turnstile"
)

// persistedInfra builds a gateway in production mode (Debug=false) restricted to
// the given trusted-documents allowlist.
func persistedInfra(ops map[string]string) *InfraDependencies {
	return &InfraDependencies{
		GlobalConfig:         Config{Port: 8080, RateLimit: 100, RateLimitWindowSeconds: 60, RiskBlockThreshold: 90, RiskPoWThreshold: 50, PoWDifficulty: 8},
		Redis:                mocked.NewMockKVStore(),
		Geo:                  geoip.NewMockResolver(geoip.GeoInfo{CountryCode: "US", Resolved: true}),
		Turnstile:            turnstile.AlwaysValid(),
		OIDCClient:           fakeOIDC{},
		AuthFlowClient:       fakeAuthnFlow{},
		SessionClient:        fakeAuthnFlow{},
		LinkedIdentityClient: fakeAuthnFlow{},
		PersistedOps:         ops,
	}
}

func postRaw(t *testing.T, h http.Handler, payload map[string]any) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

func TestPersistedAllowlistRunsKnownHash(t *testing.T) {
	t.Parallel()

	const hash = "op-start-auth"
	doc := `mutation { startAuth(input:{method:EMAIL_OTP, identifier:"a@test", captchaToken:"tok"}) { transitionId } }`
	h := newHandler(persistedInfra(map[string]string{hash: doc}))

	_, out := postRaw(t, h, map[string]any{
		"extensions": map[string]any{"persistedQuery": map[string]any{"version": 1, "sha256Hash": hash}},
	})
	if _, ok := out["errors"]; ok {
		t.Fatalf("known persisted hash should execute, got %v", out)
	}
	data, _ := out["data"].(map[string]any)
	if data["startAuth"] == nil {
		t.Fatalf("expected startAuth data, got %v", out)
	}
}

func TestPersistedAllowlistRejectsUnknownHash(t *testing.T) {
	t.Parallel()

	h := newHandler(persistedInfra(map[string]string{"known": `query { health { status } }`}))
	_, out := postRaw(t, h, map[string]any{
		"extensions": map[string]any{"persistedQuery": map[string]any{"version": 1, "sha256Hash": "unknown"}},
	})
	if _, ok := out["errors"]; !ok {
		t.Fatalf("unknown hash should be rejected, got %v", out)
	}
}

func TestPersistedAllowlistRejectsRawQuery(t *testing.T) {
	t.Parallel()

	h := newHandler(persistedInfra(map[string]string{"known": `query { health { status } }`}))
	_, out := postRaw(t, h, map[string]any{"query": `query { health { status } }`})
	if _, ok := out["errors"]; !ok {
		t.Fatalf("raw ad-hoc query should be rejected in production, got %v", out)
	}
}

func TestDebugModeAllowsRawAndIntrospection(t *testing.T) {
	t.Parallel()

	// gqlInfra sets Debug=true.
	h := newHandler(gqlInfra(fakeAuthnFlow{}, turnstile.AlwaysValid(), nil, mocked.NewMockKVStore()))

	_, raw := postGraphQL(t, h, `query { health { status } }`, "")
	if _, ok := raw["errors"]; ok {
		t.Fatalf("debug mode should allow raw queries, got %v", raw)
	}

	_, intro := postGraphQL(t, h, `query { __schema { queryType { name } } }`, "")
	if _, ok := intro["errors"]; ok {
		t.Fatalf("debug mode should allow introspection, got %v", intro)
	}
}

func TestProductionDisablesIntrospection(t *testing.T) {
	t.Parallel()

	h := newHandler(persistedInfra(map[string]string{"intro": `query { __schema { queryType { name } } }`}))
	// Introspection is off in production: even an allowlisted introspection
	// document fails validation because the schema is opaque.
	_, out := postRaw(t, h, map[string]any{
		"extensions": map[string]any{"persistedQuery": map[string]any{"version": 1, "sha256Hash": "intro"}},
	})
	if _, ok := out["errors"]; !ok {
		t.Fatalf("introspection must be disabled in production, got %v", out)
	}
}
