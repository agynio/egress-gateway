package egress

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"

	"sync"
	"testing"
	"time"

	egressv1 "github.com/agynio/egress-gateway/.gen/go/agynio/api/egress/v1"
	"google.golang.org/grpc"
)

const testResourceID = "6b3f2c66-8f4e-4dff-9f2f-25b6a7f3d111"

func privateRule(id string, resourceID string, effect *egressv1.EgressRuleEffect) *egressv1.EgressRule {
	return &egressv1.EgressRule{Meta: &egressv1.EntityMeta{Id: id}, Matcher: &egressv1.EgressRuleMatcher{PrivateResourceId: resourceID}, Effect: effect}
}

type privateRuleClient struct {
	rules     []*egressv1.EgressRule
	resources map[string]*egressv1.PrivateResourceInfo
	err       error
}

func (f *privateRuleClient) ListEgressRulesByAgent(context.Context, *egressv1.ListEgressRulesByAgentRequest, ...grpc.CallOption) (*egressv1.ListEgressRulesByAgentResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &egressv1.ListEgressRulesByAgentResponse{EgressRules: f.rules, PrivateResources: f.resources}, nil
}

func (f *privateRuleClient) ListEgressRulesByEnvironment(context.Context, *egressv1.ListEgressRulesByEnvironmentRequest, ...grpc.CallOption) (*egressv1.ListEgressRulesByEnvironmentResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &egressv1.ListEgressRulesByEnvironmentResponse{}, nil
}

// fakeZitiDialer hands out one end of a pipe and records the dialed service.
type fakeZitiDialer struct {
	mu       sync.Mutex
	dialed   []string
	upstream func() net.Conn
	err      error
}

func (f *fakeZitiDialer) DialService(serviceName string) (net.Conn, error) {
	f.mu.Lock()
	f.dialed = append(f.dialed, serviceName)
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return f.upstream(), nil
}

func (f *fakeZitiDialer) dialedServices() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.dialed...)
}

type recordingSpanEmitter struct {
	mu    sync.Mutex
	spans []Span
}

func (r *recordingSpanEmitter) EmitSpan(_ context.Context, span Span) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.spans = append(r.spans, span)
	return nil
}

func (r *recordingSpanEmitter) waitForSpan(t *testing.T) Span {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		if len(r.spans) > 0 {
			span := r.spans[0]
			r.mu.Unlock()
			return span
		}
		r.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("no span emitted")
	return Span{}
}

func privateConn(serverConn net.Conn, interceptPort string) DataPlaneConn {
	return &namedConn{
		DataPlaneConn: &fakeDataPlaneConn{Conn: serverConn, dialerIdentityID: "ziti-agent-1", appData: []byte(`{"dst_protocol":"tcp","dst_hostname":"gitlab.corp","dst_port":"` + interceptPort + `"}`)},
		serviceName:   "private-" + testResourceID,
	}
}

func privateDataPlane(t *testing.T, ruleClient RuleClient, dialer ZitiDialer, listener DataPlaneListener, spans SpanEmitter) *DataPlaneServer {
	t.Helper()
	clock := &fakeClock{now: time.Now()}
	rules := NewRuleCache(ruleClient, time.Minute, clock)
	secrets := NewSecretCache(&fakeSecretClient{values: []string{"token"}}, time.Minute, clock)
	forwarder := NewForwarder(time.Second)
	if dialer != nil {
		forwarder = forwarder.WithPrivateUpstreams(dialer, secrets)
	}
	var observed *Observability
	if spans != nil {
		observed = NewObservability(spans, nil, clock)
	}
	runtime := NewRuntime(rules, NewEvaluator(secrets), forwarder, observed)
	identity := NewIdentityResolver(&fakeZitiIdentityClient{}, &fakeAgentIdentityClient{})
	server := NewDataPlaneServer(listener, runtime, identity, NewLeafCertificateCache(testCA(t), time.Minute, 2, clock))
	if dialer != nil {
		server = server.WithZitiDialer(dialer)
	}
	return server
}

// A workload holding no rule naming the resource is spliced byte-for-byte to
// the resource's upstream service for the dialed intercept port.
func TestPrivateConnSplicedWhenNoRuleNamesResource(t *testing.T) {
	upstreamServer, upstreamGateway := net.Pipe()
	dialer := &fakeZitiDialer{upstream: func() net.Conn { return upstreamGateway }}
	serverConn, clientConn := net.Pipe()
	listener := &fakeDataPlaneListener{conn: privateConn(serverConn, "443")}
	spans := &recordingSpanEmitter{}
	server := privateDataPlane(t, &privateRuleClient{rules: []*egressv1.EgressRule{rule("rule-1", "api.example.com", allowEffect())}}, dialer, listener, spans)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.Serve(ctx) }()

	if _, err := clientConn.Write([]byte("raw bytes")); err != nil {
		t.Fatalf("write client bytes: %v", err)
	}
	buf := make([]byte, len("raw bytes"))
	if _, err := io.ReadFull(upstreamServer, buf); err != nil {
		t.Fatalf("read spliced bytes: %v", err)
	}
	if string(buf) != "raw bytes" {
		t.Fatalf("spliced bytes = %q", string(buf))
	}
	if _, err := upstreamServer.Write([]byte("reply")); err != nil {
		t.Fatalf("write upstream reply: %v", err)
	}
	reply := make([]byte, len("reply"))
	if _, err := io.ReadFull(clientConn, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	clientConn.Close()
	upstreamServer.Close()

	if dialed := dialer.dialedServices(); len(dialed) != 1 || dialed[0] != "private-"+testResourceID+"-upstream-443" {
		t.Fatalf("dialed services = %v", dialed)
	}
	span := spans.waitForSpan(t)
	if span.Attributes["egress.outcome"] != string(OutcomeSpliced) {
		t.Fatalf("span outcome = %v", span.Attributes["egress.outcome"])
	}
	if _, hasMethod := span.Attributes["egress.method"]; hasMethod {
		t.Fatal("a spliced span must carry no method")
	}
	if span.Attributes["egress.private_resource_id"] != testResourceID {
		t.Fatalf("span private_resource_id = %v", span.Attributes["egress.private_resource_id"])
	}
}

// With the EgressRules service unreachable and the cache cold, a mediated
// connection is refused rather than passed through uninspected.
func TestPrivateConnRefusedWhenRulesUnavailable(t *testing.T) {
	dialer := &fakeZitiDialer{upstream: func() net.Conn { panic("must not dial") }}
	serverConn, clientConn := net.Pipe()
	listener := &fakeDataPlaneListener{conn: privateConn(serverConn, "443")}
	spans := &recordingSpanEmitter{}
	server := privateDataPlane(t, &privateRuleClient{err: errors.New("egress rules unavailable")}, dialer, listener, spans)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.Serve(ctx) }()

	// The gateway closes the connection without exchanging a byte.
	buf := make([]byte, 1)
	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := clientConn.Read(buf); err == nil {
		t.Fatal("expected the connection to be closed")
	}
	if dialed := dialer.dialedServices(); len(dialed) != 0 {
		t.Fatalf("a refused connection must not dial upstream, got %v", dialed)
	}
	span := spans.waitForSpan(t)
	if span.Attributes["egress.outcome"] != string(OutcomeRulesUnavailable) {
		t.Fatalf("span outcome = %v", span.Attributes["egress.outcome"])
	}
	if span.StatusCode != "ERROR" {
		t.Fatalf("span status = %s", span.StatusCode)
	}
}

// A caller with an attached rule naming the resource has its plaintext HTTP
// inspected: the credential is injected and the upstream leg rides the
// resource's per-port ziti service.
func TestPrivateConnInspectedWithInjection(t *testing.T) {
	upstreamServer, upstreamGateway := net.Pipe()
	dialer := &fakeZitiDialer{upstream: func() net.Conn { return upstreamGateway }}
	serverConn, clientConn := net.Pipe()
	listener := &fakeDataPlaneListener{conn: privateConn(serverConn, "80")}
	ruleClient := &privateRuleClient{
		rules:     []*egressv1.EgressRule{privateRule("rule-1", testResourceID, injectEffect(headerValue("X-Token", "sekret")))},
		resources: map[string]*egressv1.PrivateResourceInfo{testResourceID: {InterceptHost: "gitlab.corp", Protocol: egressv1.EgressPrivateResourceProtocol_EGRESS_PRIVATE_RESOURCE_PROTOCOL_HTTP}},
	}
	server := privateDataPlane(t, ruleClient, dialer, listener, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.Serve(ctx) }()

	go func() {
		if _, err := clientConn.Write([]byte("GET /api/v4/projects HTTP/1.1\r\nHost: gitlab.corp\r\nConnection: close\r\n\r\n")); err != nil {
			return
		}
	}()

	upstreamReader := bufioReader(upstreamServer)
	request, err := http.ReadRequest(upstreamReader)
	if err != nil {
		t.Fatalf("read upstream request: %v", err)
	}
	if request.Header.Get("X-Token") != "sekret" {
		t.Fatalf("upstream X-Token = %q", request.Header.Get("X-Token"))
	}
	if request.Host != "gitlab.corp" {
		t.Fatalf("upstream host = %q", request.Host)
	}
	if _, err := upstreamServer.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")); err != nil {
		t.Fatalf("write upstream response: %v", err)
	}
	response, err := http.ReadResponse(bufioReader(clientConn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", response.StatusCode)
	}
	if dialed := dialer.dialedServices(); len(dialed) != 1 || dialed[0] != "private-"+testResourceID+"-upstream-80" {
		t.Fatalf("dialed services = %v", dialed)
	}
}

// A request the rule's narrowing excludes is forwarded unchanged, not
// bypassed with a 404: only the presence of an attached rule decides whether
// the connection is inspected.
func TestPrivateRequestOutsideRuleNarrowingIsForwarded(t *testing.T) {
	upstreamServer, upstreamGateway := net.Pipe()
	dialer := &fakeZitiDialer{upstream: func() net.Conn { return upstreamGateway }}
	serverConn, clientConn := net.Pipe()
	listener := &fakeDataPlaneListener{conn: privateConn(serverConn, "80")}
	narrowed := privateRule("rule-1", testResourceID, injectEffect(headerValue("X-Token", "sekret")))
	narrowed.Matcher.Methods = []string{"POST"}
	ruleClient := &privateRuleClient{
		rules:     []*egressv1.EgressRule{narrowed},
		resources: map[string]*egressv1.PrivateResourceInfo{testResourceID: {InterceptHost: "gitlab.corp", Protocol: egressv1.EgressPrivateResourceProtocol_EGRESS_PRIVATE_RESOURCE_PROTOCOL_HTTP}},
	}
	server := privateDataPlane(t, ruleClient, dialer, listener, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.Serve(ctx) }()

	go func() {
		_, _ = clientConn.Write([]byte("GET /api HTTP/1.1\r\nHost: gitlab.corp\r\nConnection: close\r\n\r\n"))
	}()

	request, err := http.ReadRequest(bufioReader(upstreamServer))
	if err != nil {
		t.Fatalf("read upstream request: %v", err)
	}
	if request.Header.Get("X-Token") != "" {
		t.Fatal("an excluded request must not carry the injection")
	}
	if _, err := upstreamServer.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")); err != nil {
		t.Fatalf("write upstream response: %v", err)
	}
	response, err := http.ReadResponse(bufioReader(clientConn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", response.StatusCode)
	}
}

func TestEvaluatorSeparatesPublicAndPrivateDestinations(t *testing.T) {
	evaluator := NewEvaluator(NewSecretCache(&fakeSecretClient{}, time.Minute, &fakeClock{now: time.Now()}))
	rules := []*egressv1.EgressRule{
		rule("rule-public", "gitlab.corp", denyEffect()),
		privateRule("rule-private", testResourceID, allowEffect()),
	}

	privateContext := RequestContext{Method: "GET", Host: "gitlab.corp", Port: 443, PrivateResource: &PrivateResourceContext{ID: testResourceID, InterceptHost: "gitlab.corp", Scheme: "https"}}
	evaluation, err := evaluator.Evaluate(context.Background(), privateContext, rules)
	if err != nil {
		t.Fatalf("evaluate private: %v", err)
	}
	if evaluation.Outcome != OutcomeAllow || len(evaluation.MatchedRules) != 1 || evaluation.MatchedRules[0].GetMeta().GetId() != "rule-private" {
		t.Fatalf("private evaluation = %+v", evaluation)
	}

	publicContext := RequestContext{Method: "GET", Host: "gitlab.corp", Port: 443}
	evaluation, err = evaluator.Evaluate(context.Background(), publicContext, rules)
	if err != nil {
		t.Fatalf("evaluate public: %v", err)
	}
	if evaluation.Outcome != OutcomeDeny || len(evaluation.MatchedRules) != 1 || evaluation.MatchedRules[0].GetMeta().GetId() != "rule-public" {
		t.Fatalf("public evaluation = %+v", evaluation)
	}
}

func TestRuleCacheInvalidatePrivateResource(t *testing.T) {
	client := &privateRuleClient{
		rules:     []*egressv1.EgressRule{privateRule("rule-1", testResourceID, allowEffect())},
		resources: map[string]*egressv1.PrivateResourceInfo{testResourceID: {InterceptHost: "gitlab.corp", Protocol: egressv1.EgressPrivateResourceProtocol_EGRESS_PRIVATE_RESOURCE_PROTOCOL_HTTPS}},
	}
	cache := NewRuleCache(client, time.Minute, &fakeClock{now: time.Now()})
	ruleSet, err := cache.RuleSetFor(context.Background(), "agent-1", "")
	if err != nil {
		t.Fatalf("rule set: %v", err)
	}
	if ruleSet.PrivateResources[testResourceID].GetInterceptHost() != "gitlab.corp" {
		t.Fatalf("resource info = %+v", ruleSet.PrivateResources)
	}

	client.resources = map[string]*egressv1.PrivateResourceInfo{testResourceID: {InterceptHost: "gitlab.renamed.corp", Protocol: egressv1.EgressPrivateResourceProtocol_EGRESS_PRIVATE_RESOURCE_PROTOCOL_HTTPS}}
	cache.InvalidatePrivateResource(testResourceID)
	ruleSet, err = cache.RuleSetFor(context.Background(), "agent-1", "")
	if err != nil {
		t.Fatalf("rule set after invalidation: %v", err)
	}
	if ruleSet.PrivateResources[testResourceID].GetInterceptHost() != "gitlab.renamed.corp" {
		t.Fatalf("stale resource info survived invalidation: %+v", ruleSet.PrivateResources)
	}
}

func TestPrivateResourceIDFromConn(t *testing.T) {
	serverConn, _ := net.Pipe()
	defer serverConn.Close()
	base := &fakeDataPlaneConn{Conn: serverConn}
	if _, ok := privateResourceIDFromConn(base); ok {
		t.Fatal("a conn without a service name must not resolve")
	}
	if _, ok := privateResourceIDFromConn(&namedConn{DataPlaneConn: base, serviceName: "egress-rule-" + testResourceID}); ok {
		t.Fatal("a per-rule service must not resolve as private")
	}
	if _, ok := privateResourceIDFromConn(&namedConn{DataPlaneConn: base, serviceName: "private-not-a-uuid"}); ok {
		t.Fatal("a malformed name must not resolve")
	}
	id, ok := privateResourceIDFromConn(&namedConn{DataPlaneConn: base, serviceName: "private-" + testResourceID})
	if !ok || id != testResourceID {
		t.Fatalf("resolved %q ok=%v", id, ok)
	}
}
