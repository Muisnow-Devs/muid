package geoip

import (
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// fakeHandle is a test readerHandle returning a fixed country tagged with a
// version, so reloads are observable.
type fakeHandle struct {
	version string
	closed  bool
}

func (f *fakeHandle) lookup(net.IP) (GeoInfo, error) {
	return GeoInfo{CountryCode: f.version, Resolved: true}, nil
}

func (f *fakeHandle) Close() error {
	f.closed = true
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

func writeTempDB(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "GeoLite2-City.mmdb")
	if err := os.WriteFile(path, []byte("placeholder"), 0o600); err != nil {
		t.Fatalf("write temp db: %v", err)
	}
	return path
}
