package geoip

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeHandle is a test readerHandle returning a fixed country tagged with a
// version, so reloads are observable.
type fakeHandle struct {
	version string
	closed  atomic.Bool
}

func (f *fakeHandle) lookup(net.IP) (GeoInfo, error) {
	return GeoInfo{CountryCode: f.version, Resolved: true}, nil
}

func (f *fakeHandle) Close() error {
	f.closed.Store(true)
	return nil
}

func TestResolveInvalidIP(t *testing.T) {
	t.Parallel()

	path := writeTempDB(t)
	r, err := newResolver(Config{Path: path}, func(string) (readerHandle, error) {
		return &fakeHandle{version: "US"}, nil
	})
	if err != nil {
		t.Fatalf("newResolver: %v", err)
	}
	defer r.Close()

	if _, err := r.Resolve("not-an-ip"); err != ErrInvalidIP {
		t.Fatalf("expected ErrInvalidIP, got %v", err)
	}
}

func TestResolveReturnsHandleData(t *testing.T) {
	t.Parallel()

	path := writeTempDB(t)
	r, err := newResolver(Config{Path: path}, func(string) (readerHandle, error) {
		return &fakeHandle{version: "JP"}, nil
	})
	if err != nil {
		t.Fatalf("newResolver: %v", err)
	}
	defer r.Close()

	info, err := r.Resolve("8.8.8.8")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if info.CountryCode != "JP" || !info.Resolved || info.IP != "8.8.8.8" {
		t.Fatalf("unexpected GeoInfo: %+v", info)
	}
}

func TestReloadOnModTimeChange(t *testing.T) {
	t.Parallel()

	path := writeTempDB(t)

	var mu sync.Mutex
	version := "v1"
	opened := 0
	open := func(string) (readerHandle, error) {
		mu.Lock()
		defer mu.Unlock()
		opened++
		return &fakeHandle{version: version}, nil
	}

	r, err := newResolver(Config{Path: path, ReloadInterval: time.Hour}, open)
	if err != nil {
		t.Fatalf("newResolver: %v", err)
	}
	defer r.Close()

	info, _ := r.Resolve("8.8.8.8")
	if info.CountryCode != "v1" {
		t.Fatalf("initial country = %q, want v1", info.CountryCode)
	}

	// Unchanged file: reload is a no-op, no reopen.
	if err := r.reload(); err != nil {
		t.Fatalf("reload (unchanged): %v", err)
	}
	if opened != 1 {
		t.Fatalf("expected no reopen for unchanged file, opened=%d", opened)
	}

	// Bump version + modtime, then reload should swap in the new database.
	mu.Lock()
	version = "v2"
	mu.Unlock()
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
	if err := r.reload(); err != nil {
		t.Fatalf("reload (changed): %v", err)
	}
	if opened != 2 {
		t.Fatalf("expected reopen after modtime change, opened=%d", opened)
	}
	info, _ = r.Resolve("8.8.8.8")
	if info.CountryCode != "v2" {
		t.Fatalf("after reload country = %q, want v2", info.CountryCode)
	}
}

func TestCloseJoinsBlockedReloadAndPreventsReopen(t *testing.T) {
	t.Parallel()

	path := writeTempDB(t)
	reloadStarted := make(chan struct{})
	releaseReload := make(chan struct{})
	var calls atomic.Int32
	initial := &fakeHandle{version: "v1"}
	var reloaded *fakeHandle
	open := func(string) (readerHandle, error) {
		if calls.Add(1) == 1 {
			return initial, nil
		}
		reloaded = &fakeHandle{version: "v2"}
		close(reloadStarted)
		<-releaseReload
		return reloaded, nil
	}

	r, err := newResolver(Config{Path: path, ReloadInterval: time.Millisecond}, open)
	if err != nil {
		t.Fatalf("newResolver: %v", err)
	}
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
	r.StartWatch(context.Background())

	select {
	case <-reloadStarted:
	case <-time.After(time.Second):
		t.Fatal("watcher did not begin reload")
	}
	closeResult := make(chan error, 1)
	go func() { closeResult <- r.Close() }()
	select {
	case err := <-closeResult:
		t.Fatalf("Close returned before reload finished: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	close(releaseReload)
	select {
	case err := <-closeResult:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not join watcher")
	}
	if !initial.closed.Load() {
		t.Fatal("initial handle was not closed")
	}
	if reloaded == nil || !reloaded.closed.Load() {
		t.Fatal("handle opened during shutdown was not closed")
	}
	if r.current.Load() != nil {
		t.Fatal("resolver retained a handle after Close")
	}

	r.StartWatch(context.Background())
	time.Sleep(10 * time.Millisecond)
	if got := calls.Load(); got != 2 {
		t.Fatalf("open calls after restart attempt = %d, want 2", got)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func writeTempDB(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "GeoLite2-City.mmdb")
	if err := os.WriteFile(path, []byte("placeholder"), 0o600); err != nil {
		t.Fatalf("write temp db: %v", err)
	}
	return path
}
