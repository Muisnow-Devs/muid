package httpx

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	muidlog "sanzi.io/muid/pkg/log"
)

func TestRequestBodyLimitRejectsOversizedBodies(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		contentLength int64
	}{
		{name: "known content length", contentLength: 5},
		{name: "chunked body", contentLength: -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			called := false
			handler := requestBodyLimit(4, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				called = true
			}))
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("12345"))
			req.ContentLength = tt.contentLength
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if called {
				t.Fatal("downstream handler was called")
			}
			if rec.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusRequestEntityTooLarge)
			}
			if got := rec.Body.String(); got != requestTooLargeBody {
				t.Fatalf("body = %q, want %q", got, requestTooLargeBody)
			}
			if got := rec.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
				t.Fatalf("Content-Type = %q", got)
			}
		})
	}
}

func TestRequestTimeoutBuffersDownstreamResponse(t *testing.T) {
	t.Parallel()

	handlerDone := make(chan struct{})
	handler := Budget(BudgetConfig{RequestTimeout: 10 * time.Millisecond, MaxConcurrent: 1})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("partial"))
		<-r.Context().Done()
		_, _ = w.Write([]byte("late"))
		close(handlerDone)
	}))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusGatewayTimeout)
	}
	if got := rec.Body.String(); got != requestTimeoutBody {
		t.Fatalf("body = %q, want %q", got, requestTimeoutBody)
	}
	select {
	case <-handlerDone:
	case <-time.After(time.Second):
		t.Fatal("handler goroutine did not exit")
	}
}

func TestRequestTimeoutReturnsWhileStuckHandlerRemainsBounded(t *testing.T) {
	t.Parallel()

	started := make(chan struct{})
	release := make(chan struct{})
	handlerDone := make(chan struct{})
	handler := Budget(BudgetConfig{RequestTimeout: 10 * time.Millisecond, MaxConcurrent: 1})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		close(started)
		<-release
		close(handlerDone)
	}))
	rec := httptest.NewRecorder()

	start := time.Now()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
		t.Fatalf("timeout response took %v", elapsed)
	}
	select {
	case <-started:
	default:
		t.Fatal("handler was not started")
	}
	select {
	case <-handlerDone:
		t.Fatal("stuck handler unexpectedly exited")
	default:
	}
	if rec.Code != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusGatewayTimeout)
	}
	close(release)
	select {
	case <-handlerDone:
	case <-time.After(time.Second):
		t.Fatal("handler did not finish after release")
	}
}

func TestBudgetCapsStuckHandlersAndRestoresCapacity(t *testing.T) {
	t.Parallel()

	const capacity = 2
	release := make(chan struct{})
	started := make(chan struct{}, capacity)
	var calls atomic.Int32
	var active atomic.Int32
	var maximum atomic.Int32
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls.Add(1)
		current := active.Add(1)
		for {
			observed := maximum.Load()
			if current <= observed || maximum.CompareAndSwap(observed, current) {
				break
			}
		}
		started <- struct{}{}
		<-release
		active.Add(-1)
	})
	handler := Budget(BudgetConfig{
		RequestTimeout: 10 * time.Millisecond,
		MaxConcurrent:  capacity,
	})(next)
	budgeted := handler.(*budgetHandler)

	for range capacity {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		if rec.Code != http.StatusGatewayTimeout {
			t.Fatalf("admitted status = %d, want %d", rec.Code, http.StatusGatewayTimeout)
		}
		<-started
	}

	start := time.Now()
	saturated := httptest.NewRecorder()
	handler.ServeHTTP(saturated, httptest.NewRequest(http.MethodGet, "/", nil))
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("saturated rejection took %v", elapsed)
	}
	if saturated.Code != http.StatusServiceUnavailable {
		t.Fatalf("saturated status = %d, want %d", saturated.Code, http.StatusServiceUnavailable)
	}
	if got := saturated.Body.String(); got != requestBusyBody {
		t.Fatalf("saturated body = %q, want %q", got, requestBusyBody)
	}
	if got := calls.Load(); got != capacity {
		t.Fatalf("handler calls = %d, want %d", got, capacity)
	}
	if got := maximum.Load(); got != capacity {
		t.Fatalf("maximum active handlers = %d, want %d", got, capacity)
	}

	close(release)
	deadline := time.Now().Add(time.Second)
	for len(budgeted.semaphore) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := len(budgeted.semaphore); got != 0 {
		t.Fatalf("capacity was not restored: %d slots remain occupied", got)
	}

	afterRelease := httptest.NewRecorder()
	handler.ServeHTTP(afterRelease, httptest.NewRequest(http.MethodGet, "/", nil))
	if afterRelease.Code != http.StatusOK {
		t.Fatalf("status after capacity return = %d, want %d", afterRelease.Code, http.StatusOK)
	}
}

func TestHealthBypassesSaturatedApplicationBudget(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	started := make(chan struct{})
	application := Budget(BudgetConfig{
		RequestTimeout: 10 * time.Millisecond,
		MaxConcurrent:  1,
	})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		close(started)
		<-release
	}))
	budgeted := application.(*budgetHandler)
	root := http.NewServeMux()
	root.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	root.Handle("/", application)
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	handler := Chain(root,
		TraceID,
		Logging,
		Recover,
		SecurityHeaders,
		CORS(CORSConfig{AllowedOrigins: []string{"https://app.example"}}),
	)

	appRequest := httptest.NewRequest(http.MethodGet, "/application", nil)
	appRequest = appRequest.WithContext(muidlog.WithLogger(appRequest.Context(), logger))
	appResponse := httptest.NewRecorder()
	handler.ServeHTTP(appResponse, appRequest)
	<-started
	if appResponse.Code != http.StatusGatewayTimeout {
		t.Fatalf("application status = %d, want %d", appResponse.Code, http.StatusGatewayTimeout)
	}

	healthRequest := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	healthRequest.Header.Set("Origin", "https://app.example")
	healthRequest = healthRequest.WithContext(muidlog.WithLogger(healthRequest.Context(), logger))
	healthResponse := httptest.NewRecorder()
	handler.ServeHTTP(healthResponse, healthRequest)
	if healthResponse.Code != http.StatusOK {
		t.Fatalf("health status while saturated = %d, want %d", healthResponse.Code, http.StatusOK)
	}
	if got := healthResponse.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("health security header = %q", got)
	}
	if got := healthResponse.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example" {
		t.Fatalf("health CORS origin = %q", got)
	}

	saturated := httptest.NewRecorder()
	handler.ServeHTTP(saturated, appRequest.Clone(appRequest.Context()))
	if saturated.Code != http.StatusServiceUnavailable {
		t.Fatalf("saturated application status = %d, want %d", saturated.Code, http.StatusServiceUnavailable)
	}
	close(release)
	waitForCapacity(t, budgeted)
}

type latePanicValue struct {
	secret string
}

type synchronizedBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *synchronizedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buffer.Write(p)
}

func (b *synchronizedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buffer.String()
}

func TestBudgetLogsLatePanicOnceAndRestoresCapacity(t *testing.T) {
	t.Parallel()

	const secret = "must-not-be-logged"
	release := make(chan struct{})
	started := make(chan struct{})
	budgetMiddleware := Budget(BudgetConfig{
		RequestTimeout: 10 * time.Millisecond,
		MaxConcurrent:  1,
	})
	application := budgetMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		close(started)
		<-release
		panic(latePanicValue{secret: secret})
	}))
	budgeted := application.(*budgetHandler)
	var logs synchronizedBuffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	handler := Chain(application, TraceID, Logging, Recover, SecurityHeaders)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(muidlog.TraceIDKey, "late-panic-trace")
	ctx := muidlog.WithLogger(req.Context(), logger)
	ctx = muidlog.WithAttrs(ctx, slog.String("trace_id", "late-panic-trace"))
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	<-started
	if rec.Code != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusGatewayTimeout)
	}
	close(release)
	waitForCapacity(t, budgeted)

	entries := logs.String()
	if got := strings.Count(entries, "gateway panic after request timeout"); got != 1 {
		t.Fatalf("late panic log count = %d, want 1: %s", got, entries)
	}
	if !strings.Contains(entries, "late-panic-trace") {
		t.Fatalf("late panic log omitted trace id: %s", entries)
	}
	if strings.Contains(entries, secret) {
		t.Fatalf("late panic log exposed panic value: %s", entries)
	}
}

func TestBudgetRepanicsBeforeDeadlineForOuterRecovery(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	handler := Chain(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("expected") }),
		TraceID,
		Logging,
		Recover,
		Budget(BudgetConfig{RequestTimeout: time.Second, MaxConcurrent: 1}),
	)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(muidlog.WithLogger(req.Context(), logger))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

func waitForCapacity(t *testing.T, budget *budgetHandler) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for len(budget.semaphore) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := len(budget.semaphore); got != 0 {
		t.Fatalf("capacity was not restored: %d slots remain occupied", got)
	}
}

func TestBudgetResponsePassesThroughOuterMiddleware(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	handler := Chain(
		http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() }),
		TraceID,
		Logging,
		Recover,
		SecurityHeaders,
		CORS(CORSConfig{AllowedOrigins: []string{"https://app.example"}, AllowCredentials: true}),
		Budget(BudgetConfig{RequestTimeout: 10 * time.Millisecond}),
	)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "https://app.example")
	req.Header.Set(muidlog.TraceIDKey, "test-trace")
	req = req.WithContext(muidlog.WithLogger(req.Context(), logger))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusGatewayTimeout)
	}
	if got := rec.Header().Get(muidlog.TraceIDKey); got != "test-trace" {
		t.Fatalf("trace header = %q", got)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("security header = %q", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example" {
		t.Fatalf("CORS origin = %q", got)
	}
	if !strings.Contains(logs.String(), `"status":504`) {
		t.Fatalf("access log did not record 504: %s", logs.String())
	}
}

func TestRequestTimeoutPropagatesParentCancellation(t *testing.T) {
	t.Parallel()

	observed := make(chan error, 1)
	started := make(chan struct{})
	handler := Budget(BudgetConfig{RequestTimeout: time.Minute, MaxConcurrent: 1})(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
		observed <- r.Context().Err()
	}))
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	done := make(chan struct{})
	go func() {
		handler.ServeHTTP(httptest.NewRecorder(), req)
		close(done)
	}()
	<-started
	cancel()

	select {
	case err := <-observed:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("context error = %v, want %v", err, context.Canceled)
		}
	case <-time.After(time.Second):
		t.Fatal("handler did not observe parent cancellation")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("request did not finish after parent cancellation")
	}
}
