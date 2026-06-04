package server

import (
	"context"
	"errors"
	"log"
	"net"
	"sync"

	"github.com/agynio/egress-gateway/internal/config"
)

type Server struct {
	cfg      config.Config
	listener net.Listener
	mu       sync.Mutex
	closed   bool
}

func New(cfg config.Config) *Server {
	return &Server{cfg: cfg}
}

func (s *Server) Run(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.cfg.GRPCAddress)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.listener = listener
	s.mu.Unlock()
	log.Printf("egress-gateway listening on %s", s.cfg.GRPCAddress)

	go func() {
		<-ctx.Done()
		s.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if s.isClosed() {
				return nil
			}
			return err
		}
		if err := conn.Close(); err != nil {
			log.Printf("close placeholder connection: %v", err)
		}
	}
}

func (s *Server) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
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
