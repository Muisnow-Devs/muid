package httpx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"sanzi.io/muid/pkg/errutil"
	"sanzi.io/muid/pkg/log"
)

const (
	requestTimeoutBody  = `{"error":"request timeout"}`
	requestTooLargeBody = `{"error":"request body too large"}`
	requestBusyBody     = `{"error":"server busy"}`

	// DefaultMaxConcurrentRequests bounds application handlers, including ones
	// that ignore cancellation after their client has received a timeout.
	DefaultMaxConcurrentRequests = 256
)

// BudgetConfig configures request-level resource limits. Zero values use the
// package defaults.
type BudgetConfig struct {
	RequestTimeout time.Duration
	MaxBodyBytes   int64
	// MaxConcurrent bounds admitted application handlers. Saturated budgets
	// reject promptly with 503; defaults to DefaultMaxConcurrentRequests.
	MaxConcurrent int
}

// Budget bounds and buffers application handling. At most MaxConcurrent handler
// goroutines may remain active, including handlers that ignore cancellation
// after a 504 response. Saturated budgets reject promptly with 503 without
// starting another goroutine. Budget must be installed inside observability,
// recovery, security-header, and CORS middleware so its responses inherit those
// policies and access logging records the transmitted status.
func Budget(cfg BudgetConfig) Middleware {
	if cfg.RequestTimeout <= 0 {
		cfg.RequestTimeout = defaultRequestTimeout
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = defaultMaxBodyBytes
	}
	if cfg.MaxConcurrent <= 0 {
		cfg.MaxConcurrent = DefaultMaxConcurrentRequests
	}
	semaphore := make(chan struct{}, cfg.MaxConcurrent)
	return func(next http.Handler) http.Handler {
		return &budgetHandler{
			next:           next,
			requestTimeout: cfg.RequestTimeout,
			maxBodyBytes:   cfg.MaxBodyBytes,
			semaphore:      semaphore,
		}
	}
}

type budgetHandler struct {
	next           http.Handler
	requestTimeout time.Duration
	maxBodyBytes   int64
	semaphore      chan struct{}
}

const (
	requestPending int32 = iota
	handlerCompleted
	requestTimedOut
)

func (h *budgetHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	select {
	case h.semaphore <- struct{}{}:
	case <-r.Context().Done():
		return
	default:
		writeBudgetError(w, http.StatusServiceUnavailable, requestBusyBody)
		return
	}

	if !readRequestBody(w, r, h.maxBodyBytes) {
		<-h.semaphore
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), h.requestTimeout)
	defer cancel()
	tw := &timeoutResponseWriter{header: make(http.Header)}
	resultCh := make(chan handlerResult, 1)
	var outcome atomic.Int32
	go func() {
		result := runHandler(h.next, tw, r.WithContext(ctx))
		if handlerFinishedBeforeDeadline(ctx) && outcome.CompareAndSwap(requestPending, handlerCompleted) {
			<-h.semaphore
			resultCh <- result
			return
		}
		outcome.CompareAndSwap(requestPending, requestTimedOut)
		if result.panicked {
			log.LogUnexpected(r.Context(), "gateway panic after request timeout",
				fmt.Sprintf("panic_type=%T", result.panicValue))
		}
		<-h.semaphore
		resultCh <- result
	}()

	select {
	case result := <-resultCh:
		if outcome.Load() == requestTimedOut {
			h.writeTimeout(w, ctx, tw)
			return
		}
		h.finalizeCompleted(w, tw, result)
	case <-ctx.Done():
		if outcome.CompareAndSwap(requestPending, requestTimedOut) {
			h.writeTimeout(w, ctx, tw)
			return
		}
		if outcome.Load() == handlerCompleted {
			result := <-resultCh
			h.finalizeCompleted(w, tw, result)
			return
		}
		h.writeTimeout(w, ctx, tw)
	}
}

func (*budgetHandler) finalizeCompleted(w http.ResponseWriter, tw *timeoutResponseWriter, result handlerResult) {
	if result.panicked {
		panic(result.panicValue)
	}
	tw.writeTo(w)
}

func (*budgetHandler) writeTimeout(w http.ResponseWriter, ctx context.Context, tw *timeoutResponseWriter) {
	tw.timeout()
	if deadlineExceeded(ctx) {
		writeBudgetError(w, http.StatusGatewayTimeout, requestTimeoutBody)
	}
}

func handlerFinishedBeforeDeadline(ctx context.Context) bool {
	return ctx.Err() == nil && !deadlineExceeded(ctx)
}

func deadlineExceeded(ctx context.Context) bool {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return true
	}
	deadline, ok := ctx.Deadline()
	return ok && !time.Now().Before(deadline)
}

type handlerResult struct {
	panicValue any
	panicked   bool
}

func runHandler(next http.Handler, w http.ResponseWriter, r *http.Request) (result handlerResult) {
	defer func() {
		if recovered := recover(); recovered != nil {
			result.panicValue = recovered
			result.panicked = true
		}
	}()
	next.ServeHTTP(w, r)
	return result
}

func requestBodyLimit(maxBytes int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if readRequestBody(w, r, maxBytes) {
			next.ServeHTTP(w, r)
		}
	})
}

func readRequestBody(w http.ResponseWriter, r *http.Request, maxBytes int64) bool {
	if r.Body == nil {
		return true
	}
	if r.ContentLength > maxBytes {
		closeRequestBody(r.Body)
		writeBudgetError(w, http.StatusRequestEntityTooLarge, requestTooLargeBody)
		return false
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxBytes+1))
	closeRequestBody(r.Body)
	if err != nil {
		writeBudgetError(w, http.StatusBadRequest, `{"error":"invalid request body"}`)
		return false
	}
	if int64(len(body)) > maxBytes {
		writeBudgetError(w, http.StatusRequestEntityTooLarge, requestTooLargeBody)
		return false
	}

	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	return true
}

func closeRequestBody(body io.Closer) {
	errutil.Close(body)
}

type timeoutResponseWriter struct {
	mu          sync.Mutex
	header      http.Header
	body        bytes.Buffer
	status      int
	wroteHeader bool
	timedOut    atomic.Bool
}

func (w *timeoutResponseWriter) Header() http.Header {
	return w.header
}

func (w *timeoutResponseWriter) WriteHeader(status int) {
	if w.timedOut.Load() {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.timedOut.Load() || w.wroteHeader {
		return
	}
	w.status = status
	w.wroteHeader = true
}

func (w *timeoutResponseWriter) Write(body []byte) (int, error) {
	if w.timedOut.Load() {
		return 0, http.ErrHandlerTimeout
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.timedOut.Load() {
		return 0, http.ErrHandlerTimeout
	}
	if !w.wroteHeader {
		w.status = http.StatusOK
		w.wroteHeader = true
	}
	return w.body.Write(body)
}

func (w *timeoutResponseWriter) timeout() {
	w.timedOut.Store(true)
}

func (w *timeoutResponseWriter) writeTo(dst http.ResponseWriter) {
	w.mu.Lock()
	defer w.mu.Unlock()

	copyHeader(dst.Header(), w.header)
	status := w.status
	if !w.wroteHeader {
		status = http.StatusOK
	}
	dst.WriteHeader(status)
	_, _ = dst.Write(w.body.Bytes())
}

func copyHeader(dst, src http.Header) {
	for key, values := range src {
		dst[key] = append([]string(nil), values...)
	}
}

func writeBudgetError(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}
