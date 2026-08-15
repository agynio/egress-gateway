package egress

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/net/http2"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	egressv1 "github.com/agynio/egress-gateway/.gen/go/agynio/api/egress/v1"
	"github.com/google/uuid"
)

type DataPlaneListener interface {
	Accept() (DataPlaneConn, error)
	Close() error
}

type DataPlaneConn interface {
	net.Conn
	DialerIdentityID() string
	AppData() []byte
}

type DataPlaneServer struct {
	listener DataPlaneListener
	runtime  *Runtime
	identity *IdentityResolver
	certs    *LeafCertificateCache
	dialer   ZitiDialer
}

func NewDataPlaneServer(listener DataPlaneListener, runtime *Runtime, identity *IdentityResolver, certs *LeafCertificateCache) *DataPlaneServer {
	if listener == nil {
		panic("data-plane listener is required")
	}
	if runtime == nil {
		panic("egress runtime is required")
	}
	if identity == nil {
		panic("identity resolver is required")
	}
	if certs == nil {
		panic("leaf certificate cache is required")
	}
	return &DataPlaneServer{listener: listener, runtime: runtime, identity: identity, certs: certs}
}

// WithZitiDialer supplies the dialer for mediated private resources' upstream
// services. Without it, connections to private-<id> services are refused.
func (s *DataPlaneServer) WithZitiDialer(dialer ZitiDialer) *DataPlaneServer {
	s.dialer = dialer
	return s
}

func (s *DataPlaneServer) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		if err := s.listener.Close(); err != nil {
			log.Printf("close ziti data-plane listener: %v", err)
		}
	}()

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go s.handleConn(ctx, conn)
	}
}

func (s *DataPlaneServer) Close() error {
	return s.listener.Close()
}

func (s *DataPlaneServer) handleConn(ctx context.Context, conn DataPlaneConn) {
	defer conn.Close()

	if resourceID, ok := privateResourceIDFromConn(conn); ok {
		s.handlePrivateConn(ctx, conn, resourceID)
		return
	}

	agent, err := s.identity.ResolveAgent(ctx, conn.DialerIdentityID())
	if err != nil {
		log.Printf("resolve egress dialer identity: %v", err)
		return
	}
	destination, err := DestinationFromAppData(conn.AppData())
	if err != nil {
		log.Printf("resolve egress destination: %v", err)
		return
	}
	// The wire decides the scheme, not the reported port: a rule covering both
	// 80 and 443 collapses to one tunneler listener, and every connection
	// through it arrives claiming the lower port.
	sniffed, isTLS, err := sniffTLSClientHello(conn)
	if err != nil {
		log.Printf("sniff egress connection: %v", err)
		return
	}
	if isTLS {
		destination.Scheme = "https"
		if err := s.serveHTTPS(ctx, sniffed, agent, destination); err != nil {
			log.Printf("serve ziti https egress: %v", err)
		}
		return
	}
	destination.Scheme = "http"
	if err := s.serveHTTP(ctx, sniffed, agent, destination); err != nil {
		log.Printf("serve ziti http egress: %v", err)
	}
}

type serviceNamedConn interface {
	ServiceName() string
}

type interceptPortedConn interface {
	InterceptPorts() []int
}

// resolveInterceptPort decides which of the resource's intercept ports the
// caller dialed. The dialing sidecar's app data is trusted only when it names
// one of the service's own ports -- this deployment's diverter reports its
// local port instead of the dialed one -- and a single-port resource needs no
// signal at all. Zero means the port cannot be determined.
func resolveInterceptPort(conn DataPlaneConn) int {
	ports := []int{}
	if ported, ok := conn.(interceptPortedConn); ok {
		ports = ported.InterceptPorts()
	}
	reported := 0
	if destination, err := DestinationFromAppData(conn.AppData()); err == nil {
		reported = destination.Port
	}
	for _, port := range ports {
		if port == reported {
			return reported
		}
	}
	if len(ports) == 1 {
		return ports[0]
	}
	return 0
}

// privateResourceIDFromConn reads the mediated resource's id off the OpenZiti
// service the connection arrived on. Nothing in the byte stream is trusted
// for routing.
func privateResourceIDFromConn(conn DataPlaneConn) (string, bool) {
	named, ok := conn.(serviceNamedConn)
	if !ok {
		return "", false
	}
	raw, found := strings.CutPrefix(named.ServiceName(), "private-")
	if !found {
		return "", false
	}
	resourceID, err := uuid.Parse(raw)
	if err != nil {
		return "", false
	}
	return resourceID.String(), true
}

// handlePrivateConn decides what a connection to a mediated private resource
// gets, before touching a byte of it: inspection when an attached rule names
// the resource, a byte-for-byte splice when none does, and a refusal when the
// rule set cannot be determined -- guessing splice would silently drop a deny
// or a credential.
func (s *DataPlaneServer) handlePrivateConn(ctx context.Context, conn DataPlaneConn, resourceID string) {
	dialer, err := s.identity.ResolveDialer(ctx, conn.DialerIdentityID())
	if err != nil {
		log.Printf("resolve private resource dialer identity: %v", err)
		return
	}
	interceptPort := resolveInterceptPort(conn)
	if interceptPort == 0 {
		log.Printf("refusing private resource %s connection: dialed intercept port cannot be determined", resourceID)
		s.runtime.EmitConnOutcome(ctx, privateRequestContext(dialer.Agent, resourceID, "", "", 0), OutcomeUpstreamError)
		return
	}
	// Only workloads can hold rules; every other principal type reached the
	// resource through an access grant and is spliced untouched.
	if !dialer.IsWorkload {
		s.splicePrivateConn(ctx, conn, resourceID, interceptPort, dialer.Agent)
		return
	}
	ruleSet, err := s.runtime.RuleSetFor(ctx, dialer.Agent)
	if err != nil {
		log.Printf("refusing private resource %s connection: rules unavailable: %v", resourceID, err)
		s.runtime.EmitConnOutcome(ctx, privateRequestContext(dialer.Agent, resourceID, "", "", interceptPort), OutcomeRulesUnavailable)
		return
	}
	if !ruleSetNamesResource(ruleSet, resourceID) {
		s.splicePrivateConn(ctx, conn, resourceID, interceptPort, dialer.Agent)
		return
	}
	info := ruleSet.PrivateResources[resourceID]
	if info == nil {
		// The rules name the resource but its denormalized fields could not
		// be resolved; inspecting on guesses could dial the wrong scheme.
		log.Printf("refusing private resource %s connection: resource fields unavailable", resourceID)
		s.runtime.EmitConnOutcome(ctx, privateRequestContext(dialer.Agent, resourceID, "", "", interceptPort), OutcomeRulesUnavailable)
		return
	}
	scheme := "http"
	if info.GetProtocol() == egressv1.EgressPrivateResourceProtocol_EGRESS_PRIVATE_RESOURCE_PROTOCOL_HTTPS {
		scheme = "https"
	}
	privateResource := &PrivateResourceContext{ID: resourceID, InterceptHost: info.GetInterceptHost(), Scheme: scheme}
	destination := Destination{Scheme: scheme, Host: info.GetInterceptHost(), Port: interceptPort}
	sniffed, isTLS, err := sniffTLSClientHello(conn)
	if err != nil {
		log.Printf("sniff private resource connection: %v", err)
		return
	}
	if isTLS {
		if err := s.servePrivateHTTPS(ctx, sniffed, dialer.Agent, destination, privateResource); err != nil {
			log.Printf("serve private https egress: %v", err)
		}
		return
	}
	if err := s.servePrivateHTTP(ctx, sniffed, dialer.Agent, destination, privateResource); err != nil {
		log.Printf("serve private http egress: %v", err)
	}
}

func (s *DataPlaneServer) servePrivateHTTPS(ctx context.Context, conn net.Conn, agent AgentContext, destination Destination, resource *PrivateResourceContext) error {
	tlsConn := tls.Server(conn, &tls.Config{GetCertificate: s.certificateForClientHello, NextProtos: []string{"h2", "http/1.1"}})
	if err := tlsConn.Handshake(); err != nil {
		s.runtime.EmitTLSFailure(ctx, privateRequestContext(agent, resource.ID, destination.Scheme, destination.Host, destination.Port))
		return fmt.Errorf("tls handshake: %w", err)
	}
	defer tlsConn.Close()
	if tlsConn.ConnectionState().NegotiatedProtocol == "h2" {
		return s.servePrivateHTTP2(ctx, tlsConn, agent, destination, resource)
	}
	return s.servePrivateHTTP(ctx, tlsConn, agent, destination, resource)
}

func (s *DataPlaneServer) servePrivateHTTP2(ctx context.Context, conn net.Conn, agent AgentContext, destination Destination, resource *PrivateResourceContext) error {
	server := &http2.Server{}
	server.ServeConn(conn, &http2.ServeConnOpts{Context: ctx, Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		requestContext := RequestContextFromHTTP(agent, destination.Scheme, destination.Host, destination.Port, req, uuid.NewString())
		requestContext.PrivateResource = resource
		if err := s.runtime.ServeRequest(ctx, w, req, requestContext); err != nil {
			log.Printf("serve private h2 egress request: %v", err)
		}
	})})
	return nil
}

func (s *DataPlaneServer) servePrivateHTTP(ctx context.Context, conn net.Conn, agent AgentContext, destination Destination, resource *PrivateResourceContext) error {
	reader := bufio.NewReader(conn)
	req, err := ReadHTTPRequest(reader)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return fmt.Errorf("read request: %w", err)
	}
	req.RemoteAddr = conn.RemoteAddr().String()
	req.RequestURI = ""
	requestContext := RequestContextFromHTTP(agent, destination.Scheme, destination.Host, destination.Port, req, uuid.NewString())
	requestContext.PrivateResource = resource
	response := newConnResponseWriter(conn)
	runtimeErr := s.runtime.ServeRequest(ctx, response, req, requestContext)
	if runtimeErr == nil || !response.sentHeader {
		if err := response.finish(); err != nil {
			return fmt.Errorf("write response: %w", err)
		}
	}
	drainAfterResponse(conn, reader)
	if runtimeErr != nil {
		return fmt.Errorf("serve private egress request: %w", runtimeErr)
	}
	return nil
}

// splicePrivateConn passes a mediated connection through byte-for-byte:
// nothing decrypted, no substituted certificate -- a caller whose access came
// from a grant completes TLS against the target's own certificate.
func (s *DataPlaneServer) splicePrivateConn(ctx context.Context, conn DataPlaneConn, resourceID string, interceptPort int, agent AgentContext) {
	requestContext := privateRequestContext(agent, resourceID, "", "", interceptPort)
	if s.dialer == nil || interceptPort == 0 {
		log.Printf("refusing private resource %s splice: no upstream dialer or intercept port", resourceID)
		s.runtime.EmitConnOutcome(ctx, requestContext, OutcomeUpstreamError)
		return
	}
	upstream, err := s.dialer.DialService(privateUpstreamServiceName(resourceID, interceptPort))
	if err != nil {
		log.Printf("dial private resource %s upstream: %v", resourceID, err)
		s.runtime.EmitConnOutcome(ctx, requestContext, OutcomeUpstreamError)
		return
	}
	defer upstream.Close()
	bytesIn, bytesOut := spliceConns(conn, upstream)
	metrics := RequestMetrics{Context: requestContext, Outcome: OutcomeSpliced, BytesIn: bytesIn, BytesOut: bytesOut, StartedAt: requestContext.ReceivedTime, CompletedAt: time.Now()}
	s.runtime.EmitMetrics(ctx, metrics)
}

func spliceConns(client net.Conn, upstream net.Conn) (int64, int64) {
	done := make(chan int64, 1)
	go func() {
		bytesIn, _ := io.Copy(upstream, client)
		halfClose(upstream)
		done <- bytesIn
	}()
	bytesOut, _ := io.Copy(client, upstream)
	halfClose(client)
	bytesIn := <-done
	return bytesIn, bytesOut
}

func halfClose(conn net.Conn) {
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

func privateRequestContext(agent AgentContext, resourceID string, scheme string, host string, port int) RequestContext {
	return RequestContext{
		Agent:           agent,
		Scheme:          scheme,
		Host:            host,
		Port:            port,
		RequestID:       uuid.NewString(),
		ReceivedTime:    time.Now(),
		PrivateResource: &PrivateResourceContext{ID: resourceID, InterceptHost: host, Scheme: scheme},
	}
}

func ruleSetNamesResource(ruleSet RuleSet, resourceID string) bool {
	for _, rule := range ruleSet.Rules {
		if rule.GetMatcher().GetPrivateResourceId() == resourceID {
			return true
		}
	}
	return false
}

// destinationFromRequestHost takes the upstream from the request's own Host,
// which architecture makes authoritative alongside the SNI. The connection
// metadata cannot serve: the workload's pod-local diverter REDIRECTs the
// connection before the tunneler records it, so it reports the diverter's
// own 127.0.0.1:<port> rather than what the client dialled.
func destinationFromRequestHost(destination Destination, req *http.Request) Destination {
	host := strings.TrimSuffix(strings.TrimSpace(req.Host), ".")
	if host == "" {
		return destination
	}
	port := 0
	if bare, portValue, err := net.SplitHostPort(host); err == nil {
		parsed, convErr := strconv.Atoi(portValue)
		if convErr != nil {
			return destination
		}
		host, port = bare, parsed
	}
	if port == 0 {
		port = 80
		if destination.Scheme == "https" {
			port = 443
		}
	}
	destination.Host = host
	destination.Port = port
	return destination
}

// peekConn replays the bytes consumed while sniffing.
type peekConn struct {
	net.Conn
	reader io.Reader
}

func (c *peekConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

// sniffTLSClientHello reports whether the connection opens with a TLS record:
// handshake content type followed by a 3.x major version. Everything the
// gateway proxies is either that or a plaintext HTTP request line.
func sniffTLSClientHello(conn net.Conn) (net.Conn, bool, error) {
	reader := bufio.NewReader(conn)
	prefix, err := reader.Peek(2)
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return &peekConn{Conn: conn, reader: reader}, false, nil
		}
		return nil, false, err
	}
	return &peekConn{Conn: conn, reader: reader}, prefix[0] == 0x16 && prefix[1] == 0x03, nil
}

func (s *DataPlaneServer) serveHTTPS(ctx context.Context, conn net.Conn, agent AgentContext, destination Destination) error {
	tlsConn := tls.Server(conn, &tls.Config{GetCertificate: s.certificateForClientHello, NextProtos: []string{"h2", "http/1.1"}})
	if err := tlsConn.Handshake(); err != nil {
		requestContext := RequestContext{Agent: agent, Scheme: destination.Scheme, Host: destination.Host, Port: destination.Port, RequestID: uuid.NewString()}
		s.runtime.EmitTLSFailure(ctx, requestContext)
		return fmt.Errorf("tls handshake: %w", err)
	}
	defer tlsConn.Close()
	if name := tlsConn.ConnectionState().ServerName; name != "" {
		destination.Host = strings.TrimSuffix(name, ".")
		destination.Port = 443
	}
	if tlsConn.ConnectionState().NegotiatedProtocol == "h2" {
		return s.serveHTTP2(ctx, tlsConn, agent, destination)
	}
	return s.serveHTTP(ctx, tlsConn, agent, destination)
}

func (s *DataPlaneServer) serveHTTP2(ctx context.Context, conn net.Conn, agent AgentContext, destination Destination) error {
	server := &http2.Server{}
	server.ServeConn(conn, &http2.ServeConnOpts{Context: ctx, Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		destination := destinationFromRequestHost(destination, req)
		requestContext := RequestContextFromHTTP(agent, destination.Scheme, destination.Host, destination.Port, req, uuid.NewString())
		if err := s.runtime.ServeRequest(ctx, w, req, requestContext); err != nil {
			log.Printf("serve h2 egress request: %v", err)
		}
	})})
	return nil
}

func (s *DataPlaneServer) serveHTTP(ctx context.Context, conn net.Conn, agent AgentContext, destination Destination) error {
	reader := bufio.NewReader(conn)
	req, err := ReadHTTPRequest(reader)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return fmt.Errorf("read request: %w", err)
	}
	req.RemoteAddr = conn.RemoteAddr().String()
	req.RequestURI = ""
	destination = destinationFromRequestHost(destination, req)
	requestContext := RequestContextFromHTTP(agent, destination.Scheme, destination.Host, destination.Port, req, uuid.NewString())
	response := newConnResponseWriter(conn)
	runtimeErr := s.runtime.ServeRequest(ctx, response, req, requestContext)
	if runtimeErr == nil || !response.sentHeader {
		if err := response.finish(); err != nil {
			return fmt.Errorf("write response: %w", err)
		}
	}
	// The response is close-delimited, so the deferred conn.Close() must not
	// race it: half-close to flush + signal EOF, then drain the client so the
	// full close doesn't reset an undelivered response over the ziti circuit.
	drainAfterResponse(conn, reader)
	if runtimeErr != nil {
		return fmt.Errorf("serve egress request: %w", runtimeErr)
	}
	return nil
}

// gracefulDrainTimeout bounds how long we wait for the client to close its
// side after we half-close, so a misbehaving client can't block the conn.
const gracefulDrainTimeout = 10 * time.Second

func drainAfterResponse(conn net.Conn, reader io.Reader) {
	cw, ok := conn.(interface{ CloseWrite() error })
	if !ok {
		// No half-close support: rely on the deferred full Close to signal EOF.
		return
	}
	if err := cw.CloseWrite(); err != nil {
		return
	}
	// Half-close flushed the response and sent EOF; wait for the client to
	// close its side (bounded) so the full Close doesn't reset the circuit.
	_ = conn.SetReadDeadline(time.Now().Add(gracefulDrainTimeout))
	_, _ = io.Copy(io.Discard, reader)
}

func (s *DataPlaneServer) certificateForClientHello(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	host := strings.TrimSuffix(hello.ServerName, ".")
	if host == "" {
		return nil, errors.New("client hello missing server name")
	}
	return s.certs.Certificate(host)
}

type Destination struct {
	Scheme string
	Host   string
	Port   int
}

type zitiAppData struct {
	Protocol string `json:"dst_protocol"`
	Port     string `json:"dst_port"`
	Hostname string `json:"dst_hostname"`
	IP       string `json:"dst_ip"`
}

func DestinationFromAppData(appData []byte) (Destination, error) {
	if len(appData) == 0 {
		return Destination{}, errors.New("missing ziti destination app data")
	}
	var payload zitiAppData
	if err := json.Unmarshal(appData, &payload); err != nil {
		return Destination{}, fmt.Errorf("decode ziti destination app data: %w", err)
	}
	host := payload.Hostname
	if host == "" {
		host = payload.IP
	}
	if host == "" {
		return Destination{}, errors.New("ziti destination app data missing host")
	}
	port, err := strconv.Atoi(payload.Port)
	if err != nil {
		return Destination{}, fmt.Errorf("parse ziti destination port: %w", err)
	}
	if port < 1 || port > 65535 {
		return Destination{}, fmt.Errorf("ziti destination port %d out of range", port)
	}
	scheme := schemeFromProtocolAndPort(payload.Protocol, port)
	return Destination{Scheme: scheme, Host: host, Port: port}, nil
}

func schemeFromProtocolAndPort(protocol string, port int) string {
	if strings.EqualFold(protocol, "tls") || port == 443 {
		return "https"
	}
	return "http"
}

type connResponseWriter struct {
	conn        net.Conn
	header      http.Header
	statusCode  int
	wroteHeader bool
	sentHeader  bool
}

func newConnResponseWriter(conn net.Conn) *connResponseWriter {
	return &connResponseWriter{conn: conn, header: http.Header{"Connection": []string{"close"}}}
}

func (w *connResponseWriter) Header() http.Header {
	return w.header
}

func (w *connResponseWriter) WriteHeader(statusCode int) {
	if w.wroteHeader {
		return
	}
	w.statusCode = statusCode
	w.wroteHeader = true
}

func (w *connResponseWriter) Write(body []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if err := w.writeHeader(); err != nil {
		return 0, err
	}
	return w.conn.Write(body)
}

func (w *connResponseWriter) finish() error {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.writeHeader()
}

func (w *connResponseWriter) writeHeader() error {
	if w.sentHeader {
		return nil
	}
	if !w.wroteHeader {
		panic("response status is required")
	}
	statusText := http.StatusText(w.statusCode)
	if statusText == "" {
		statusText = "status code " + strconv.Itoa(w.statusCode)
	}
	response := &http.Response{
		StatusCode:    w.statusCode,
		Status:        strconv.Itoa(w.statusCode) + " " + statusText,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        w.header,
		Body:          http.NoBody,
		ContentLength: -1,
		Close:         true,
	}
	w.sentHeader = true
	return response.Write(w.conn)
}
