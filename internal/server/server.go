package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"

	agentsv1 "github.com/agynio/egress-gateway/.gen/go/agynio/api/agents/v1"
	egressv1 "github.com/agynio/egress-gateway/.gen/go/agynio/api/egress/v1"
	meteringv1 "github.com/agynio/egress-gateway/.gen/go/agynio/api/metering/v1"
	secretsv1 "github.com/agynio/egress-gateway/.gen/go/agynio/api/secrets/v1"
	zitimanagementv1 "github.com/agynio/egress-gateway/.gen/go/agynio/api/ziti_management/v1"
	"github.com/agynio/egress-gateway/internal/config"
	"github.com/agynio/egress-gateway/internal/egress"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
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
	dataPlane, zitiCtx, grpcConns, err := s.buildDataPlane()
	if err != nil {
		return err
	}
	defer closeGRPCConns(grpcConns)
	defer zitiCtx.Close()

	listener, err := net.Listen("tcp", s.cfg.GRPCAddress)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.listener = listener
	s.mu.Unlock()
	log.Printf("egress-gateway admin listening on %s", s.cfg.GRPCAddress)
	log.Printf("egress-gateway ziti data-plane listening")

	go func() {
		<-ctx.Done()
		s.Close()
	}()

	dataPlaneErr := make(chan error, 1)
	go func() {
		dataPlaneErr <- dataPlane.Serve(ctx)
	}()

	adminErr := make(chan error, 1)
	go func() {
		err := s.server.Serve(listener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) && !s.isClosed() {
			adminErr <- err
			return
		}
		adminErr <- nil
	}()

	select {
	case err := <-dataPlaneErr:
		if err != nil && ctx.Err() == nil {
			s.Close()
			return err
		}
		return <-adminErr
	case err := <-adminErr:
		if err != nil {
			return err
		}
		return <-dataPlaneErr
	}
}

func (s *Server) buildDataPlane() (*egress.DataPlaneServer, egress.ZitiContext, []*grpc.ClientConn, error) {
	zitiCtx, err := egress.LoadZitiContext(s.cfg.ZitiIdentityFile)
	if err != nil {
		return nil, nil, nil, err
	}
	listener, err := egress.ListenForEgressServices(zitiCtx, s.cfg.ZitiServiceName)
	if err != nil {
		zitiCtx.Close()
		return nil, nil, nil, err
	}
	ca, err := egress.LoadCertificateAuthority(s.cfg.EgressCACertPath, s.cfg.EgressCAKeyPath)
	if err != nil {
		listener.Close()
		zitiCtx.Close()
		return nil, nil, nil, err
	}
	grpcConns, err := s.grpcConns()
	if err != nil {
		listener.Close()
		zitiCtx.Close()
		return nil, nil, nil, err
	}
	ruleClient := egressv1.NewEgressRulesServiceClient(grpcConns[0])
	secretClient := secretsv1.NewSecretsServiceClient(grpcConns[1])
	zitiClient := zitimanagementv1.NewZitiManagementServiceClient(grpcConns[2])
	agentClient := agentsv1.NewAgentsServiceClient(grpcConns[3])
	meteringClient := meteringv1.NewMeteringServiceClient(grpcConns[4])
	clock := egress.SystemClock{}
	rules := egress.NewRuleCache(ruleClient, s.cfg.RuleCacheTTL, clock)
	secrets := egress.NewSecretCache(secretClient, s.cfg.SecretCacheTTL, clock)
	evaluator := egress.NewEvaluator(secrets)
	forwarder := egress.NewForwarder(s.cfg.ForwardTimeout)
	observed := egress.NewObservability(nil, meteringClient, clock)
	runtime := egress.NewRuntime(rules, evaluator, forwarder, observed)
	identity := egress.NewIdentityResolver(zitiClient, agentClient)
	certs := egress.NewLeafCertificateCache(ca, s.cfg.LeafCertTTL, s.cfg.LeafCertCacheSize, clock)
	return egress.NewDataPlaneServer(listener, runtime, identity, certs), zitiCtx, grpcConns, nil
}

func (s *Server) grpcConns() ([]*grpc.ClientConn, error) {
	targets := []string{s.cfg.EgressAddress, s.cfg.SecretsAddress, s.cfg.ZitiManagementAddress, s.cfg.AgentsAddress, s.cfg.MeteringAddress}
	conns := make([]*grpc.ClientConn, 0, len(targets))
	for _, target := range targets {
		conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			closeGRPCConns(conns)
			return nil, fmt.Errorf("create grpc client %s: %w", target, err)
		}
		conns = append(conns, conn)
	}
	return conns, nil
}

func closeGRPCConns(conns []*grpc.ClientConn) {
	for _, conn := range conns {
		if err := conn.Close(); err != nil {
			log.Printf("close grpc connection: %v", err)
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
