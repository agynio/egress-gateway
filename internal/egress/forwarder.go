package egress

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	defaultMaxHeaderBytes = 1 << 20
)

var hopByHopHeaders = map[string]struct{}{
	"Connection":          {},
	"Keep-Alive":          {},
	"Proxy-Authenticate":  {},
	"Proxy-Authorization": {},
	"Te":                  {},
	"Trailer":             {},
	"Transfer-Encoding":   {},
	"Upgrade":             {},
}

type Forwarder struct {
	transport http.RoundTripper
	timeout   time.Duration
}

func NewForwarder(timeout time.Duration) *Forwarder {
	if timeout <= 0 {
		panic("forward timeout must be positive")
	}
	return &Forwarder{transport: http.DefaultTransport, timeout: timeout}
}

func NewForwarderWithTransport(timeout time.Duration, transport http.RoundTripper) *Forwarder {
	if timeout <= 0 {
		panic("forward timeout must be positive")
	}
	if transport == nil {
		panic("transport is required")
	}
	return &Forwarder{transport: transport, timeout: timeout}
}

func (f *Forwarder) ServeHTTP(w http.ResponseWriter, r *http.Request, reqCtx RequestContext, evaluation Evaluation) RequestMetrics {
	start := time.Now()
	metrics := RequestMetrics{Context: reqCtx, Outcome: evaluation.Outcome, MatchedRuleIDs: matchedRuleIDs(evaluation.MatchedRules)}
	if isUpgradeRequest(r) {
		metrics.Outcome = OutcomeUpstreamError
		http.Error(w, "egress gateway does not support upgraded connections", http.StatusUpgradeRequired)
		metrics.UpstreamStatus = http.StatusUpgradeRequired
		metrics.Latency = time.Since(start)
		return metrics
	}
	if evaluation.Outcome == OutcomeDeny {
		http.Error(w, "egress rule denied request", http.StatusForbidden)
		metrics.UpstreamStatus = http.StatusForbidden
		metrics.Latency = time.Since(start)
		return metrics
	}
	upstream, err := buildUpstreamRequest(r, reqCtx, evaluation.InjectedHeader)
	if err != nil {
		metrics.Outcome = OutcomeUpstreamError
		http.Error(w, "egress gateway could not build upstream request", http.StatusBadGateway)
		metrics.UpstreamStatus = http.StatusBadGateway
		metrics.Latency = time.Since(start)
		return metrics
	}
	ctx, cancel := context.WithTimeout(r.Context(), f.timeout)
	defer cancel()
	upstream = upstream.WithContext(ctx)
	resp, err := f.transport.RoundTrip(upstream)
	if err != nil {
		metrics.Outcome = OutcomeUpstreamError
		http.Error(w, "egress gateway upstream request failed", http.StatusBadGateway)
		metrics.UpstreamStatus = http.StatusBadGateway
		metrics.Latency = time.Since(start)
		return metrics
	}
	defer resp.Body.Close()
	copyResponseHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	bytesOut, copyErr := io.Copy(w, resp.Body)
	metrics.BytesIn = requestBodyBytes(r)
	metrics.BytesOut = bytesOut
	metrics.UpstreamStatus = resp.StatusCode
	metrics.Latency = time.Since(start)
	if copyErr != nil {
		metrics.Outcome = OutcomeUpstreamError
	}
	return metrics
}

func ReadHTTPRequest(reader io.Reader) (*http.Request, error) {
	limited := &io.LimitedReader{R: reader, N: defaultMaxHeaderBytes}
	req, err := http.ReadRequest(bufio.NewReader(limited))
	if err != nil {
		return nil, err
	}
	if limited.N == 0 {
		return nil, errors.New("request headers exceed maximum size")
	}
	return req, nil
}

func buildUpstreamRequest(source *http.Request, reqCtx RequestContext, injected http.Header) (*http.Request, error) {
	url := *source.URL
	url.Scheme = reqCtx.Scheme
	url.Host = net.JoinHostPort(reqCtx.Host, strconv.Itoa(reqCtx.Port))
	upstream, err := http.NewRequest(source.Method, url.String(), source.Body)
	if err != nil {
		return nil, err
	}
	upstream.Header = cloneHeader(source.Header)
	removeHopByHopHeaders(upstream.Header)
	for name, values := range injected {
		upstream.Header.Del(name)
		for _, value := range values {
			upstream.Header.Add(name, value)
		}
	}
	upstream.Host = reqCtx.Host
	return upstream, nil
}

func copyResponseHeaders(dst http.Header, src http.Header) {
	for name, values := range src {
		if _, ok := hopByHopHeaders[http.CanonicalHeaderKey(name)]; ok {
			continue
		}
		for _, value := range values {
			dst.Add(name, value)
		}
	}
}

func cloneHeader(header http.Header) http.Header {
	cloned := http.Header{}
	for name, values := range header {
		for _, value := range values {
			cloned.Add(name, value)
		}
	}
	return cloned
}

func removeHopByHopHeaders(header http.Header) {
	connectionHeaders := header.Values("Connection")
	for _, connectionHeader := range connectionHeaders {
		for _, name := range strings.Split(connectionHeader, ",") {
			header.Del(strings.TrimSpace(name))
		}
	}
	for name := range hopByHopHeaders {
		header.Del(name)
	}
}

func isUpgradeRequest(r *http.Request) bool {
	return r.Header.Get("Upgrade") != "" || strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

func requestBodyBytes(r *http.Request) int64 {
	if r.ContentLength > 0 {
		return r.ContentLength
	}
	return 0
}

func RequestContextFromHTTP(agent AgentContext, scheme string, host string, port int, r *http.Request, requestID string) RequestContext {
	return RequestContext{Agent: agent, Method: r.Method, Scheme: scheme, Host: host, Port: port, Path: r.URL.Path, RequestID: requestID, ReceivedTime: time.Now()}
}

func OriginalDestinationFromHostPort(address string, fallbackScheme string) (string, int, string, error) {
	host, portValue, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, "", fmt.Errorf("parse original destination: %w", err)
	}
	port, err := strconv.Atoi(portValue)
	if err != nil {
		return "", 0, "", fmt.Errorf("parse original destination port: %w", err)
	}
	scheme := fallbackScheme
	if scheme == "" {
		if port == 443 {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	return host, port, scheme, nil
}
