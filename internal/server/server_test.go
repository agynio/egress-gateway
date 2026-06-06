package server

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/agynio/egress-gateway/internal/config"
)

func TestAdminHealthDoesNotDependOnDataPlane(t *testing.T) {
	cfg := config.Config{GRPCAddress: "127.0.0.1:0", DataPlaneRetryInterval: time.Hour}
	srv := New(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()

	addr := waitForAdminAddress(t, srv)
	resp, err := http.Get("http://" + addr + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz status = %d", resp.StatusCode)
	}
	ready, err := http.Get("http://" + addr + "/readyz")
	if err != nil {
		t.Fatalf("GET /readyz: %v", err)
	}
	defer ready.Body.Close()
	if ready.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("readyz status = %d", ready.StatusCode)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not stop")
	}
}

func waitForAdminAddress(t *testing.T, srv *Server) string {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		srv.mu.Lock()
		listener := srv.listener
		srv.mu.Unlock()
		if listener != nil {
			return listener.Addr().String()
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("admin listener was not started")
	return ""
}
