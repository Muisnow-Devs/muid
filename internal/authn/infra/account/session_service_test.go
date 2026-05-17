package account

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"entgo.io/ent/dialect"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"sanzi.io/muid/infra/mocked"
	"sanzi.io/muid/internal/authn/ent"
	"sanzi.io/muid/internal/authn/ent/enttest"
	"sanzi.io/muid/internal/authn/infra/kv"
	"sanzi.io/muid/internal/session"
	sharedkv "sanzi.io/muid/pkg/shared/kv"
)

func openSessionTestDB(t *testing.T) *ent.Client {
	t.Helper()
	dsn := fmt.Sprintf(
		"file:%s?mode=memory&cache=shared&_fk=1",
		strings.ReplaceAll(t.Name(), "/", "_"),
	)
	return enttest.Open(t, dialect.SQLite, dsn)
}

func seedUserRef(t *testing.T, client *ent.Client, userID uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	err := client.UserRef.Create().
		SetID(userID).
		SetEmail(userID.String() + "@session-test.local").
		Exec(ctx)
	if err != nil {
		t.Fatalf("seed user ref: %v", err)
	}
}

func wireTokenParts(t *testing.T) (wire string, selectorB64 string, validatorSecret []byte) {
	t.Helper()
	selector := make([]byte, SelectorLength)
	validatorSecret = make([]byte, ValidatorLength)
	if _, err := rand.Read(selector); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(validatorSecret); err != nil {
		t.Fatal(err)
	}
	selectorB64 = base64.RawURLEncoding.EncodeToString(selector)
	wire = selectorB64 + "." + base64.RawURLEncoding.EncodeToString(validatorSecret)
	return wire, selectorB64, validatorSecret
}

func insertUserSession(
	t *testing.T,
	client *ent.Client,
	userID uuid.UUID,
	selector []byte,
	validatorSecret []byte,
	expiresAt time.Time,
	revokedAt time.Time,
) *ent.UserSession {
	t.Helper()
	ctx := context.Background()
	sum := sha256.Sum256(validatorSecret)
	builder := client.UserSession.Create().
		SetUserID(userID).
		SetSelector(selector).
		SetValidatorHash(sum[:]).
		SetExpiresAt(expiresAt)
	if !revokedAt.IsZero() {
		builder.SetRevokedAt(revokedAt)
	}
	row, err := builder.Save(ctx)
	if err != nil {
		t.Fatalf("insert session: %v", err)
	}
	return row
}

func newSessionService(t *testing.T, cache session.SessionCache) *sessionService {
	t.Helper()
	client := openSessionTestDB(t)
	return &sessionService{store: &Store{DB: client, SessionCache: cache}}
}

func TestIssueAuthenticatedSession_requiresExistingUser(t *testing.T) {
	t.Parallel()

	client := openSessionTestDB(t)
	ctx := context.Background()
	svc := &sessionService{store: &Store{DB: client}}

	_, err := svc.IssueAuthenticatedSession(ctx, uuid.Nil)
	if err == nil {
		t.Fatal("expected error issuing session for missing user ref")
	}
}

func TestIssueResolveRoundTrip(t *testing.T) {
	t.Parallel()

	client := openSessionTestDB(t)
	ctx := context.Background()
	userID := uuid.MustParse("00000000-0000-7000-8000-000000000020")
	seedUserRef(t, client, userID)

	svc := &sessionService{store: &Store{DB: client}}
	issued, err := svc.IssueAuthenticatedSession(ctx, userID)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	wire := issued.GetSessionContext().GetSessionToken().GetValue()

	resolved, err := svc.ResolveSessionToken(ctx, wire)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if resolved.UserID != userID {
		t.Fatalf("user id: got %v", resolved.UserID)
	}
}

func TestIssueAuthenticatedSession_uniqueSelectors(t *testing.T) {
	t.Parallel()

	client := openSessionTestDB(t)
	ctx := context.Background()
	userID := uuid.MustParse("00000000-0000-7000-8000-000000000021")
	seedUserRef(t, client, userID)

	svc := &sessionService{store: &Store{DB: client}}
	const n = 24
	selectors := make(map[string]struct{}, n)

	for range n {
		issued, err := svc.IssueAuthenticatedSession(ctx, userID)
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		selB64, _, err := ParseSessionToken(issued.GetSessionContext().GetSessionToken().GetValue())
		if err != nil {
			t.Fatal(err)
		}
		if _, dup := selectors[selB64]; dup {
			t.Fatalf("duplicate selector: %s", selB64)
		}
		selectors[selB64] = struct{}{}
	}
}

func TestResolveSessionToken_wrongValidatorDB(t *testing.T) {
	t.Parallel()

	client := openSessionTestDB(t)
	ctx := context.Background()
	userID := uuid.MustParse("00000000-0000-7000-8000-000000000022")
	seedUserRef(t, client, userID)

	selector := make([]byte, SelectorLength)
	validatorSecret := make([]byte, ValidatorLength)
	if _, err := rand.Read(selector); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(validatorSecret); err != nil {
		t.Fatal(err)
	}
	insertUserSession(t, client, userID, selector, validatorSecret, time.Now().Add(time.Hour), time.Time{})

	selectorB64 := base64.RawURLEncoding.EncodeToString(selector)
	wrongValidator := make([]byte, ValidatorLength)
	if _, err := rand.Read(wrongValidator); err != nil {
		t.Fatal(err)
	}
	wireBad := selectorB64 + "." + base64.RawURLEncoding.EncodeToString(wrongValidator)

	svc := &sessionService{store: &Store{DB: client}}
	_, err := svc.ResolveSessionToken(ctx, wireBad)
	if !errors.Is(err, session.ErrSessionNotFound) {
		t.Fatalf("wrong validator: got %v want ErrSessionNotFound", err)
	}
}

func TestResolveSessionToken_revokedAndExpiredDB(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		expiresAt time.Time
		revokedAt time.Time
		wantErr   error
	}{
		{
			name:      "revoked session",
			expiresAt: time.Now().Add(time.Hour),
			revokedAt: time.Now(),
			wantErr:   session.ErrSessionNotFound,
		},
		{
			name:      "expired session",
			expiresAt: time.Now().Add(-time.Hour),
			revokedAt: time.Time{},
			wantErr:   session.ErrSessionExpired,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			client := openSessionTestDB(t)
			ctx := context.Background()
			userID := uuid.New()
			seedUserRef(t, client, userID)

			selector := make([]byte, SelectorLength)
			validatorSecret := make([]byte, ValidatorLength)
			if _, err := rand.Read(selector); err != nil {
				t.Fatal(err)
			}
			if _, err := rand.Read(validatorSecret); err != nil {
				t.Fatal(err)
			}
			insertUserSession(t, client, userID, selector, validatorSecret, tc.expiresAt, tc.revokedAt)

			wire := base64.RawURLEncoding.EncodeToString(selector) + "." +
				base64.RawURLEncoding.EncodeToString(validatorSecret)
			svc := &sessionService{store: &Store{DB: client}}
			_, err := svc.ResolveSessionToken(ctx, wire)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("resolve: got %v want %v", err, tc.wantErr)
			}
		})
	}
}

func TestRevokeSessionToken_thenResolveNotFound(t *testing.T) {
	t.Parallel()

	client := openSessionTestDB(t)
	ctx := context.Background()
	userID := uuid.MustParse("00000000-0000-7000-8000-000000000023")
	seedUserRef(t, client, userID)

	svc := &sessionService{store: &Store{DB: client}}
	issued, err := svc.IssueAuthenticatedSession(ctx, userID)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	wire := issued.GetSessionContext().GetSessionToken().GetValue()

	if err := svc.RevokeSessionToken(ctx, wire); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	_, err = svc.ResolveSessionToken(ctx, wire)
	if !errors.Is(err, session.ErrSessionNotFound) {
		t.Fatalf("resolve after revoke: got %v", err)
	}
}

func TestRevokeSessionToken_wrongValidatorNotFound(t *testing.T) {
	t.Parallel()

	client := openSessionTestDB(t)
	ctx := context.Background()
	userID := uuid.New()
	seedUserRef(t, client, userID)

	issued, err := (&sessionService{store: &Store{DB: client}}).IssueAuthenticatedSession(ctx, userID)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	selB64, _, err := ParseSessionToken(issued.GetSessionContext().GetSessionToken().GetValue())
	if err != nil {
		t.Fatal(err)
	}
	wrongValidator := make([]byte, ValidatorLength)
	if _, err := rand.Read(wrongValidator); err != nil {
		t.Fatal(err)
	}
	wireBad := selB64 + "." + base64.RawURLEncoding.EncodeToString(wrongValidator)

	svc := &sessionService{store: &Store{DB: client}}
	if err := svc.RevokeSessionToken(ctx, wireBad); !errors.Is(err, session.ErrSessionNotFound) {
		t.Fatalf("revoke wrong validator: got %v", err)
	}
}

func TestResolveSessionToken_unknownTokenNotFound(t *testing.T) {
	t.Parallel()

	svc := newSessionService(t, nil)
	_, err := svc.ResolveSessionToken(context.Background(), validWireToken(t))
	if !errors.Is(err, session.ErrSessionNotFound) {
		t.Fatalf("unknown token: got %v", err)
	}
}

func TestResolveSessionToken_malformedVsWrongValidatorErrors(t *testing.T) {
	t.Parallel()

	svc := newSessionService(t, &mapSessionCache{entries: map[string]session.CachedSession{}})
	ctx := context.Background()

	_, malformedErr := svc.ResolveSessionToken(ctx, "not-a-token")
	if !errors.Is(malformedErr, errInvalidSessionToken) {
		t.Fatalf("malformed: got %v", malformedErr)
	}

	wire, selectorB64, validatorSecret := wireTokenParts(t)
	sum := sha256.Sum256(validatorSecret)
	svc.store.SessionCache.(*mapSessionCache).entries[selectorB64] = session.CachedSession{
		SessionID:     uuid.New(),
		UserID:        uuid.New(),
		ExpiresAt:     time.Now().Add(time.Hour),
		ValidatorHash: sum,
	}
	wrongValidator := make([]byte, ValidatorLength)
	if _, err := rand.Read(wrongValidator); err != nil {
		t.Fatal(err)
	}
	wireBad := selectorB64 + "." + base64.RawURLEncoding.EncodeToString(wrongValidator)

	_, wrongValErr := svc.ResolveSessionToken(ctx, wireBad)
	if !errors.Is(wrongValErr, session.ErrSessionNotFound) {
		t.Fatalf("wrong validator: got %v", wrongValErr)
	}

	// Cache miss (empty entries) with unknown wire — DB not-found.
	emptySvc := newSessionService(t, &mapSessionCache{entries: map[string]session.CachedSession{}})
	_, unknownErr := emptySvc.ResolveSessionToken(ctx, wire)
	if !errors.Is(unknownErr, session.ErrSessionNotFound) {
		t.Fatalf("cache miss unknown token: got %v", unknownErr)
	}
}

func TestResolveSessionToken_expiredCacheFallsThroughDB(t *testing.T) {
	t.Parallel()

	client := openSessionTestDB(t)
	ctx := context.Background()
	userID := uuid.New()
	seedUserRef(t, client, userID)

	selector := make([]byte, SelectorLength)
	validatorSecret := make([]byte, ValidatorLength)
	if _, err := rand.Read(selector); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(validatorSecret); err != nil {
		t.Fatal(err)
	}
	insertUserSession(t, client, userID, selector, validatorSecret, time.Now().Add(time.Hour), time.Time{})

	selectorB64 := base64.RawURLEncoding.EncodeToString(selector)
	sum := sha256.Sum256(validatorSecret)

	mockKV := seedExpiredSessionCacheRecord(t, selectorB64, sum, userID, time.Now().Add(-time.Minute))
	cache := kv.NewKVSessionCache(mockKV)

	svc := &sessionService{store: &Store{DB: client, SessionCache: cache}}
	wire := selectorB64 + "." + base64.RawURLEncoding.EncodeToString(validatorSecret)

	resolved, err := svc.ResolveSessionToken(ctx, wire)
	if err != nil {
		t.Fatalf("resolve after expired cache: %v", err)
	}
	if resolved.UserID != userID {
		t.Fatalf("user id: got %v want %v", resolved.UserID, userID)
	}
}

// seedExpiredSessionCacheRecord writes cache JSON with a past expires_at (Get must reject it).
func seedExpiredSessionCacheRecord(
	t *testing.T,
	selectorB64 string,
	sum [32]byte,
	userID uuid.UUID,
	expiresAt time.Time,
) sharedkv.KVStore {
	t.Helper()
	store := mocked.NewMockKVStore()
	rec := struct {
		SessionID     string `json:"session_id"`
		UserID        string `json:"user_id"`
		ExpiresAt     int64  `json:"expires_at"`
		ValidatorHash []byte `json:"validator_hash"`
	}{
		SessionID:     uuid.New().String(),
		UserID:        userID.String(),
		ExpiresAt:     expiresAt.Unix(),
		ValidatorHash: sum[:],
	}
	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	key := "muid:auth:session:sel:" + selectorB64
	if err := store.Set(context.Background(), key, data, time.Hour); err != nil {
		t.Fatal(err)
	}
	return store
}
