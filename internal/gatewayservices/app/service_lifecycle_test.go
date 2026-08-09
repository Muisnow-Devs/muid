package app

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"

	"sanzi.io/muid/pkg/errutil"
)

func TestServicesGRPCRunForcesStopAfterDrainBudget(t *testing.T) {
	t.Parallel()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { errutil.Close(listener) })

	fake := newBlockingGRPCServer()
	service := &ServicesGRPC{
		server:          fake,
		listener:        listener,
		shutdownTimeout: 10 * time.Millisecond,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- service.Run(ctx) }()

	select {
	case <-fake.serveStarted:
	case <-time.After(time.Second):
		t.Fatal("Serve was not called")
	}
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run() did not return after forced stop")
	}
	if !fake.forced.Load() {
		t.Fatal("Stop was not called after graceful drain timed out")
	}
}

type blockingGRPCServer struct {
	serveStarted    chan struct{}
	serveStopped    chan struct{}
	allowGraceful   chan struct{}
	serveStartOnce  sync.Once
	serveStopOnce   sync.Once
	gracefulEndOnce sync.Once
	forced          atomic.Bool
}

func newBlockingGRPCServer() *blockingGRPCServer {
	return &blockingGRPCServer{
		serveStarted:  make(chan struct{}),
		serveStopped:  make(chan struct{}),
		allowGraceful: make(chan struct{}),
	}
}

func (s *blockingGRPCServer) Serve(net.Listener) error {
	s.serveStartOnce.Do(func() { close(s.serveStarted) })
	<-s.serveStopped
	return grpc.ErrServerStopped
}

func (s *blockingGRPCServer) GracefulStop() {
	<-s.allowGraceful
	s.serveStopOnce.Do(func() { close(s.serveStopped) })
}

func (s *blockingGRPCServer) Stop() {
	s.forced.Store(true)
	s.gracefulEndOnce.Do(func() { close(s.allowGraceful) })
	s.serveStopOnce.Do(func() { close(s.serveStopped) })
}
