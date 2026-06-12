package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	agentsv1 "github.com/agynio/egress-gateway/.gen/go/agynio/api/agents/v1"
	egressv1 "github.com/agynio/egress-gateway/.gen/go/agynio/api/egress/v1"
	meteringv1 "github.com/agynio/egress-gateway/.gen/go/agynio/api/metering/v1"
	notificationsv1 "github.com/agynio/egress-gateway/.gen/go/agynio/api/notifications/v1"
	secretsv1 "github.com/agynio/egress-gateway/.gen/go/agynio/api/secrets/v1"
	zitimanagementv1 "github.com/agynio/egress-gateway/.gen/go/agynio/api/ziti_management/v1"
	"github.com/agynio/egress-gateway/internal/config"
	"github.com/agynio/egress-gateway/internal/egress"
	collectortracev1 "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Server struct {
	cfg          config.Config
	listener     net.Listener
	server       *http.Server
	dataPlane    *egress.DataPlaneServer
	zitiCtx      egress.ZitiContext
	clientConns  []*grpc.ClientConn
	dataPlaneErr error
	dataPlaneOK  bool
	mu           sync.Mutex
	closed       bool
}

func New(cfg config.Config) *Server {
	s := &Server{cfg: cfg}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !s.isDataPlaneReady() {
			http.Error(w, "egress gateway data plane is not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	s.server = &http.Server{Handler: mux}
	return s
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
	go s.runDataPlane(ctx)

	err = s.server.Serve(listener)
	if err != nil && !errors.Is(err, http.ErrServerClosed) && !s.isClosed() {
		return err
	}
	return nil
}

func (s *Server) runDataPlane(ctx context.Context) {
	for ctx.Err() == nil && !s.isClosed() {
		runCtx, cancel := context.WithCancel(ctx)
		dataPlane, zitiCtx, grpcConns, err := s.buildDataPlane(runCtx)
		if err != nil {
			cancel()
			s.setDataPlaneState(false, err)
			log.Printf("start ziti data plane: %v", err)
			if !sleepWithContext(ctx, s.dataPlaneRetryInterval()) {
				return
			}
			continue
		}
		s.setDataPlane(dataPlane, zitiCtx, grpcConns)
		log.Printf("egress-gateway ziti data-plane listening")
		err = dataPlane.Serve(runCtx)
		cancel()
		s.clearDataPlane()
		if ctx.Err() != nil || s.isClosed() {
			return
		}
		s.setDataPlaneState(false, err)
		log.Printf("ziti data-plane stopped: %v", err)
		if !sleepWithContext(ctx, s.dataPlaneRetryInterval()) {
			return
		}
	}
}

func (s *Server) buildDataPlane(ctx context.Context) (*egress.DataPlaneServer, egress.ZitiContext, []*grpc.ClientConn, error) {
	if err := egress.EnsureZitiIdentity(s.cfg.ZitiIdentityFile, s.cfg.ZitiEnrollmentJWTFile); err != nil {
		return nil, nil, nil, err
	}
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
	grpcConns, err := s.newGRPCConns()
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
	notificationsClient := notificationsv1.NewNotificationsServiceClient(grpcConns[5])
	traceClient := collectortracev1.NewTraceServiceClient(grpcConns[6])
	clock := egress.SystemClock{}
	rules := egress.NewRuleCache(ruleClient, s.cfg.RuleCacheTTL, clock)
	secrets := egress.NewSecretCache(secretClient, s.cfg.SecretCacheTTL, clock)
	evaluator := egress.NewEvaluator(secrets)
	forwarder := egress.NewForwarder(s.cfg.ForwardTimeout)
	spans := egress.NewOTLPSpanEmitter(traceClient)
	observed := egress.NewObservability(spans, meteringClient, clock)
	runtime := egress.NewRuntime(rules, evaluator, forwarder, observed)
	go func() {
		if err := egress.NewRuleInvalidationSubscriber(notificationsClient, rules, []string{egress.EgressRulesRoom}).Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("egress rule invalidation subscriber stopped: %v", err)
		}
	}()
	identity := egress.NewIdentityResolver(zitiClient, agentClient)
	certs := egress.NewLeafCertificateCache(ca, s.cfg.LeafCertTTL, s.cfg.LeafCertCacheSize, clock)
	return egress.NewDataPlaneServer(listener, runtime, identity, certs), zitiCtx, grpcConns, nil
}

func (s *Server) newGRPCConns() ([]*grpc.ClientConn, error) {
	targets := []string{s.cfg.EgressAddress, s.cfg.SecretsAddress, s.cfg.ZitiManagementAddress, s.cfg.AgentsAddress, s.cfg.MeteringAddress, s.cfg.NotificationsAddress, s.cfg.TracingAddress}
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

func sleepWithContext(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (s *Server) dataPlaneRetryInterval() time.Duration {
	if s.cfg.DataPlaneRetryInterval > 0 {
		return s.cfg.DataPlaneRetryInterval
	}
	return 5 * time.Second
}

func (s *Server) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	server := s.server
	listener := s.listener
	dataPlane := s.dataPlane
	zitiCtx := s.zitiCtx
	grpcConns := s.clientConns
	s.dataPlane = nil
	s.zitiCtx = nil
	s.clientConns = nil
	s.mu.Unlock()
	if dataPlane != nil {
		if err := dataPlane.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Printf("close data-plane listener: %v", err)
		}
	}
	if zitiCtx != nil {
		zitiCtx.Close()
	}
	closeGRPCConns(grpcConns)
	if server != nil {
		if err := server.Close(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("close admin server: %v", err)
		}
	}
	if listener != nil {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Printf("close listener: %v", err)
		}
	}
}

func (s *Server) setDataPlane(dataPlane *egress.DataPlaneServer, zitiCtx egress.ZitiContext, grpcConns []*grpc.ClientConn) {
	s.mu.Lock()
	s.dataPlane = dataPlane
	s.zitiCtx = zitiCtx
	s.clientConns = grpcConns
	s.dataPlaneOK = true
	s.dataPlaneErr = nil
	s.mu.Unlock()
}

func (s *Server) clearDataPlane() {
	s.mu.Lock()
	zitiCtx := s.zitiCtx
	grpcConns := s.clientConns
	s.dataPlane = nil
	s.zitiCtx = nil
	s.clientConns = nil
	s.dataPlaneOK = false
	s.mu.Unlock()
	if zitiCtx != nil {
		zitiCtx.Close()
	}
	closeGRPCConns(grpcConns)
}

func (s *Server) setDataPlaneState(ready bool, err error) {
	s.mu.Lock()
	s.dataPlaneOK = ready
	s.dataPlaneErr = err
	s.mu.Unlock()
}

func (s *Server) isDataPlaneReady() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dataPlaneOK && s.dataPlaneErr == nil
}

func (s *Server) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}
