package egress

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"

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

func (s *DataPlaneServer) handleConn(ctx context.Context, conn DataPlaneConn) {
	defer conn.Close()

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
	if destination.Scheme == "https" {
		if err := s.serveHTTPS(ctx, conn, agent, destination); err != nil {
			log.Printf("serve ziti https egress: %v", err)
		}
		return
	}
	if err := s.serveHTTP(ctx, conn, agent, destination); err != nil {
		log.Printf("serve ziti http egress: %v", err)
	}
}

func (s *DataPlaneServer) serveHTTPS(ctx context.Context, conn net.Conn, agent AgentContext, destination Destination) error {
	tlsConn := tls.Server(conn, &tls.Config{GetCertificate: s.certificateForClientHello})
	if err := tlsConn.Handshake(); err != nil {
		requestContext := RequestContext{Agent: agent, Scheme: destination.Scheme, Host: destination.Host, Port: destination.Port, RequestID: uuid.NewString()}
		s.runtime.EmitTLSFailure(ctx, requestContext)
		return fmt.Errorf("tls handshake: %w", err)
	}
	defer tlsConn.Close()
	return s.serveHTTP(ctx, tlsConn, agent, destination)
}

func (s *DataPlaneServer) serveHTTP(ctx context.Context, conn net.Conn, agent AgentContext, destination Destination) error {
	reader := bufio.NewReader(conn)
	for {
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
		response := newConnResponseWriter(conn)
		_ = s.runtime.ServeRequest(ctx, response, req, requestContext)
		if err := response.finish(); err != nil {
			return fmt.Errorf("write response: %w", err)
		}
		if shouldClose(req, response.header) {
			return nil
		}
	}
}

func (s *DataPlaneServer) certificateForClientHello(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	host := strings.TrimSuffix(hello.ServerName, ".")
	if host == "" {
		return nil, errors.New("client hello missing server name")
	}
	return s.certs.Certificate(host)
}

func shouldClose(req *http.Request, responseHeader http.Header) bool {
	return req.Close || strings.EqualFold(responseHeader.Get("Connection"), "close")
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
	body        bytes.Buffer
	statusCode  int
	wroteHeader bool
}

func newConnResponseWriter(conn net.Conn) *connResponseWriter {
	return &connResponseWriter{conn: conn, header: http.Header{}}
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
	return w.body.Write(body)
}

func (w *connResponseWriter) finish() error {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.writeHeader()
}

func (w *connResponseWriter) writeHeader() error {
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
		Body:          io.NopCloser(bytes.NewReader(w.body.Bytes())),
		ContentLength: int64(w.body.Len()),
	}
	return response.Write(w.conn)
}
