package server

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"sync"

	"github.com/agynio/egress-gateway/internal/config"
)

type Server struct {
	cfg      config.Config
	listener net.Listener
	server   *http.Server
	mu       sync.Mutex
	closed   bool
}

func New(cfg config.Config) *Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	return &Server{cfg: cfg, server: &http.Server{Handler: mux}}
}

func (s *Server) Run(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.cfg.GRPCAddress)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.listener = listener
	s.mu.Unlock()
	log.Printf("egress-gateway admin listening on %s", s.cfg.GRPCAddress)

	go func() {
		<-ctx.Done()
		s.Close()
	}()

	err = s.server.Serve(listener)
	if err != nil && !errors.Is(err, http.ErrServerClosed) && !s.isClosed() {
		return err
	}
	return nil
}

func (s *Server) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	if s.server != nil {
		if err := s.server.Close(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("close admin server: %v", err)
		}
	}
	if s.listener != nil {
		if err := s.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Printf("close listener: %v", err)
		}
	}
}

func (s *Server) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}
