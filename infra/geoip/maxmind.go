package geoip

import (
	"context"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	geoip2 "github.com/oschwald/geoip2-golang"

	"sanzi.io/muid/pkg/errutil"
	"sanzi.io/muid/pkg/log"
)

// readerHandle is the lookup surface a loaded database exposes. It is an
// interface so the watcher/reload logic can be tested without a real mmdb file.
type readerHandle interface {
	lookup(ip net.IP) (GeoInfo, error)
	io.Closer
}

// opener loads a readerHandle from a database path.
type opener func(path string) (readerHandle, error)

type loaded struct {
	handle  readerHandle
	modTime time.Time
}

// MaxMindResolver resolves IPs against a MaxMind City database and hot-reloads
// the file when it changes on disk.
type MaxMindResolver struct {
	path     string
	interval time.Duration
	open     opener

	mu      sync.Mutex
	current atomic.Pointer[loaded]
	closed  atomic.Bool

	watchMu     sync.Mutex
	watchCancel context.CancelFunc
	watchDone   chan struct{}

	closeOnce sync.Once
	closeDone chan struct{}
	closeErr  error
}

// Config configures a MaxMindResolver.
type Config struct {
	// Path is the mmdb file path (often a mounted volume).
	Path string
	// ReloadInterval is how often the file is checked for updates. Defaults
	// to 6h when <= 0.
	ReloadInterval time.Duration
}

// Open loads the database at cfg.Path and returns a resolver. The caller should
// invoke StartWatch to enable hot-reloading.
func Open(cfg Config) (*MaxMindResolver, error) {
	return newResolver(cfg, realOpen)
}

func newResolver(cfg Config, open opener) (*MaxMindResolver, error) {
	if cfg.ReloadInterval <= 0 {
		cfg.ReloadInterval = 6 * time.Hour
	}
	r := &MaxMindResolver{
		path:      cfg.Path,
		interval:  cfg.ReloadInterval,
		open:      open,
		closeDone: make(chan struct{}),
	}
	if err := r.reload(); err != nil {
		return nil, err
	}
	return r, nil
}

// Resolve implements Resolver.
func (r *MaxMindResolver) Resolve(ip string) (GeoInfo, error) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return GeoInfo{}, ErrInvalidIP
	}
	cur := r.current.Load()
	if cur == nil || cur.handle == nil {
		return GeoInfo{}, ErrUnavailable
	}
	info, err := cur.handle.lookup(parsed)
	if err != nil {
		return GeoInfo{}, err
	}
	info.IP = ip
	return info, nil
}

// StartWatch polls the database file and reloads it when its modification time
// advances, until ctx is cancelled.
func (r *MaxMindResolver) StartWatch(ctx context.Context) {
	r.watchMu.Lock()
	defer r.watchMu.Unlock()
	if r.closed.Load() || r.watchDone != nil {
		return
	}

	watchCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	r.watchCancel = cancel
	r.watchDone = done
	go r.watch(watchCtx, done)
}

func (r *MaxMindResolver) watch(ctx context.Context, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := r.reload(); err != nil && ctx.Err() == nil {
				log.Logger(ctx).Warn("geoip reload failed", "error", err.Error(), "path", r.path)
			}
		}
	}
}

// reload swaps in a freshly-opened database when the file's modtime has changed
// since the last load. It is a no-op when the file is unchanged.
func (r *MaxMindResolver) reload() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed.Load() {
		return ErrUnavailable
	}

	info, err := os.Stat(r.path)
	if err != nil {
		return err
	}
	mod := info.ModTime()

	if cur := r.current.Load(); cur != nil && cur.modTime.Equal(mod) {
		return nil
	}

	handle, err := r.open(r.path)
	if err != nil {
		return err
	}
	if r.closed.Load() {
		errutil.Close(handle)
		return ErrUnavailable
	}

	old := r.current.Swap(&loaded{handle: handle, modTime: mod})
	if old != nil && old.handle != nil {
		errutil.Close(old.handle)
	}
	return nil
}

// Close releases the loaded database.
func (r *MaxMindResolver) Close() error {
	r.closeOnce.Do(func() {
		r.closed.Store(true)

		r.watchMu.Lock()
		cancel := r.watchCancel
		done := r.watchDone
		r.watchMu.Unlock()
		if cancel != nil {
			cancel()
		}
		if done != nil {
			<-done
		}

		r.mu.Lock()
		cur := r.current.Swap(nil)
		r.mu.Unlock()
		if cur != nil && cur.handle != nil {
			r.closeErr = cur.handle.Close()
		}
		close(r.closeDone)
	})
	<-r.closeDone
	return r.closeErr
}

// realOpen is the production opener backed by geoip2.
func realOpen(path string) (readerHandle, error) {
	reader, err := geoip2.Open(path)
	if err != nil {
		return nil, err
	}
	return &geoReader{reader: reader}, nil
}

type geoReader struct {
	reader *geoip2.Reader
}

func (g *geoReader) lookup(ip net.IP) (GeoInfo, error) {
	rec, err := g.reader.City(ip)
	if err != nil {
		return GeoInfo{}, err
	}
	info := GeoInfo{
		CountryCode: rec.Country.IsoCode,
		CountryName: rec.Country.Names["en"],
		City:        rec.City.Names["en"],
		Resolved:    rec.Country.IsoCode != "",
	}
	return info, nil
}

func (g *geoReader) Close() error {
	return g.reader.Close()
}
