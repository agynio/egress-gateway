package egress

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	agentsv1 "github.com/agynio/egress-gateway/.gen/go/agynio/api/agents/v1"
	egressv1 "github.com/agynio/egress-gateway/.gen/go/agynio/api/egress/v1"
	identityv1 "github.com/agynio/egress-gateway/.gen/go/agynio/api/identity/v1"
	meteringv1 "github.com/agynio/egress-gateway/.gen/go/agynio/api/metering/v1"
	notificationsv1 "github.com/agynio/egress-gateway/.gen/go/agynio/api/notifications/v1"
	secretsv1 "github.com/agynio/egress-gateway/.gen/go/agynio/api/secrets/v1"
	zitimanagementv1 "github.com/agynio/egress-gateway/.gen/go/agynio/api/ziti_management/v1"
	"github.com/openziti/edge-api/rest_model"
	"github.com/openziti/sdk-golang/ziti"
	"github.com/openziti/sdk-golang/ziti/edge"
	collectortracev1 "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	tracev1 "go.opentelemetry.io/proto/otlp/trace/v1"
	"golang.org/x/net/http2"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestRuleCacheUsesTTL(t *testing.T) {
	clock := &fakeClock{now: time.Unix(10, 0)}
	client := &fakeRuleClient{rules: [][]*egressv1.EgressRule{{rule("a", "api.example.com", allowEffect())}, {rule("b", "api.example.com", allowEffect())}}}
	cache := NewRuleCache(client, time.Minute, clock)
	first, err := cache.Rules(context.Background(), "agent-1")
	if err != nil {
		t.Fatalf("Rules first: %v", err)
	}
	second, err := cache.Rules(context.Background(), "agent-1")
	if err != nil {
		t.Fatalf("Rules second: %v", err)
	}
	if client.calls != 1 || first[0].GetMeta().GetId() != "a" || second[0].GetMeta().GetId() != "a" {
		t.Fatalf("cache before ttl calls=%d first=%s second=%s", client.calls, first[0].GetMeta().GetId(), second[0].GetMeta().GetId())
	}
	clock.now = clock.now.Add(time.Minute)
	third, err := cache.Rules(context.Background(), "agent-1")
	if err != nil {
		t.Fatalf("Rules third: %v", err)
	}
	if client.calls != 2 || third[0].GetMeta().GetId() != "b" {
		t.Fatalf("cache after ttl calls=%d third=%s", client.calls, third[0].GetMeta().GetId())
	}
}

func TestRuleCacheServesStaleRulesOnRefreshErrorWithinWindow(t *testing.T) {
	clock := &fakeClock{now: time.Unix(10, 0)}
	refreshErr := errors.New("egress unavailable")
	var surfaced []string
	client := &fakeRuleClient{rules: [][]*egressv1.EgressRule{{rule("a", "api.example.com", allowEffect())}}, errors: []error{nil, refreshErr}}
	cache := NewRuleCacheWithStaleIfError(client, time.Minute, time.Minute, clock, func(agentID string, err error) {
		surfaced = append(surfaced, agentID+":"+err.Error())
	})
	first, err := cache.Rules(context.Background(), "agent-1")
	if err != nil {
		t.Fatalf("Rules first: %v", err)
	}
	clock.now = clock.now.Add(time.Minute)
	second, err := cache.Rules(context.Background(), "agent-1")
	if err != nil {
		t.Fatalf("Rules second: %v", err)
	}
	if first[0].GetMeta().GetId() != "a" || second[0].GetMeta().GetId() != "a" {
		t.Fatalf("stale rules first=%s second=%s", first[0].GetMeta().GetId(), second[0].GetMeta().GetId())
	}
	if len(surfaced) != 1 || !strings.Contains(surfaced[0], "egress unavailable") {
		t.Fatalf("surfaced errors = %v", surfaced)
	}
}

func TestRuleCacheReturnsErrorAfterStaleWindowExpires(t *testing.T) {
	clock := &fakeClock{now: time.Unix(10, 0)}
	refreshErr := errors.New("egress unavailable")
	client := &fakeRuleClient{rules: [][]*egressv1.EgressRule{{rule("a", "api.example.com", allowEffect())}}, errors: []error{nil, refreshErr}}
	cache := NewRuleCacheWithStaleIfError(client, time.Minute, time.Minute, clock, nil)
	if _, err := cache.Rules(context.Background(), "agent-1"); err != nil {
		t.Fatalf("Rules first: %v", err)
	}
	clock.now = clock.now.Add(2*time.Minute + time.Nanosecond)
	_, err := cache.Rules(context.Background(), "agent-1")
	if !errors.Is(err, refreshErr) {
		t.Fatalf("err = %v", err)
	}
}

func TestRuleInvalidationSubscriberInvalidatesFromNotifications(t *testing.T) {
	clock := &fakeClock{now: time.Unix(10, 0)}
	client := &fakeRuleClient{rules: [][]*egressv1.EgressRule{
		{rule("a", "api.example.com", allowEffect())},
		{rule("b", "api.example.com", allowEffect())},
		{rule("c", "api.example.com", allowEffect())},
	}}
	cache := NewRuleCache(client, time.Minute, clock)
	if _, err := cache.Rules(context.Background(), "agent-1"); err != nil {
		t.Fatalf("Rules first: %v", err)
	}
	attachmentPayload, err := structpb.NewStruct(map[string]any{"agent_id": "agent-1"})
	if err != nil {
		t.Fatalf("payload: %v", err)
	}
	subscriber := NewRuleInvalidationSubscriber(&fakeNotificationsClient{}, cache, nil)
	subscriber.handleEnvelope(&notificationsv1.NotificationEnvelope{Event: egressRuleAttachmentUpdatedEvent, Payload: attachmentPayload})
	second, err := cache.Rules(context.Background(), "agent-1")
	if err != nil {
		t.Fatalf("Rules second: %v", err)
	}
	if second[0].GetMeta().GetId() != "b" {
		t.Fatalf("attachment invalidated rule id = %s", second[0].GetMeta().GetId())
	}
	subscriber.handleEnvelope(&notificationsv1.NotificationEnvelope{Event: egressRuleUpdatedEvent})
	third, err := cache.Rules(context.Background(), "agent-1")
	if err != nil {
		t.Fatalf("Rules third: %v", err)
	}
	if third[0].GetMeta().GetId() != "c" {
		t.Fatalf("rule update invalidated rule id = %s", third[0].GetMeta().GetId())
	}
}

func TestEvaluateMatcherAndDenyWins(t *testing.T) {
	evaluator := NewEvaluator(NewSecretCache(&fakeSecretClient{}, time.Minute, &fakeClock{now: time.Now()}))
	request := RequestContext{Method: http.MethodGet, Host: "api.example.com", Port: 443, Path: "/v1/repos"}
	rules := []*egressv1.EgressRule{
		rule("1", "*.example.com", allowEffect(), withPorts(443), withMethods(http.MethodGet), withPath("/v1/*")),
		rule("2", "api.example.com", denyEffect(), withPorts(443)),
	}
	evaluation, err := evaluator.Evaluate(context.Background(), request, rules)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if evaluation.Outcome != OutcomeDeny {
		t.Fatalf("outcome = %s", evaluation.Outcome)
	}
	if len(evaluation.MatchedRules) != 2 {
		t.Fatalf("matched rules = %d", len(evaluation.MatchedRules))
	}
}

func TestEvaluateReturnsBypassForUnmatchedDestination(t *testing.T) {
	evaluator := NewEvaluator(NewSecretCache(&fakeSecretClient{}, time.Minute, &fakeClock{now: time.Now()}))
	request := RequestContext{Method: http.MethodGet, Host: "unmatched.example.com", Port: 443, Path: "/v1/repos"}
	rules := []*egressv1.EgressRule{
		rule("1", "api.example.com", allowEffect(), withPorts(443)),
	}
	evaluation, err := evaluator.Evaluate(context.Background(), request, rules)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if evaluation.Outcome != OutcomeBypass {
		t.Fatalf("outcome = %s", evaluation.Outcome)
	}
	if len(evaluation.MatchedRules) != 0 {
		t.Fatalf("matched rules = %d", len(evaluation.MatchedRules))
	}
}

func TestEvaluateInvalidPathPatternReturnsError(t *testing.T) {
	evaluator := NewEvaluator(NewSecretCache(&fakeSecretClient{}, time.Minute, &fakeClock{now: time.Now()}))
	request := RequestContext{Method: http.MethodGet, Host: "api.example.com", Port: 443, Path: "/v1/repos"}
	_, err := evaluator.Evaluate(context.Background(), request, []*egressv1.EgressRule{
		rule("1", "api.example.com", denyEffect(), withPath("[")),
	})
	if err == nil {
		t.Fatal("expected invalid path pattern to fail")
	}
}

func TestEvaluateHeaderInjectionSecretTTLAndPrecedence(t *testing.T) {
	clock := &fakeClock{now: time.Unix(100, 0)}
	secrets := &fakeSecretClient{values: []string{"first", "second"}}
	evaluator := NewEvaluator(NewSecretCache(secrets, time.Minute, clock))
	request := RequestContext{Method: http.MethodPost, Host: "api.example.com", Port: 443, Path: "/"}
	rules := []*egressv1.EgressRule{
		rule("1", "api.example.com", injectEffect(headerValue("Authorization", "literal"))),
		rule("2", "api.example.com", injectEffect(headerSecret("Authorization", "secret-1", egressv1.HeaderAuthScheme_HEADER_AUTH_SCHEME_BEARER))),
	}
	first, err := evaluator.Evaluate(context.Background(), request, rules)
	if err != nil {
		t.Fatalf("Evaluate first: %v", err)
	}
	second, err := evaluator.Evaluate(context.Background(), request, rules)
	if err != nil {
		t.Fatalf("Evaluate second: %v", err)
	}
	if got := first.InjectedHeader.Get("Authorization"); got != "Bearer first" {
		t.Fatalf("first authorization = %q", got)
	}
	if got := second.InjectedHeader.Get("Authorization"); got != "Bearer first" {
		t.Fatalf("second authorization = %q", got)
	}
	clock.now = clock.now.Add(time.Minute)
	third, err := evaluator.Evaluate(context.Background(), request, rules)
	if err != nil {
		t.Fatalf("Evaluate third: %v", err)
	}
	if got := third.InjectedHeader.Get("Authorization"); got != "Bearer second" {
		t.Fatalf("third authorization = %q", got)
	}
	if secrets.calls != 2 {
		t.Fatalf("secret calls = %d", secrets.calls)
	}
}

func TestForwarderForwardsInjectsAndRejectsWebSocket(t *testing.T) {
	var upstreamHeader string
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		upstreamHeader = r.Header.Get("X-Api-Key")
		return &http.Response{StatusCode: http.StatusCreated, Header: http.Header{"X-Upstream": []string{"ok"}}, Body: io.NopCloser(strings.NewReader("created"))}, nil
	})
	forwarder := NewForwarderWithTransport(time.Second, transport)
	req := httptest.NewRequest(http.MethodPost, "http://placeholder.local/resource?q=1", strings.NewReader("body"))
	req.Header.Set("X-Api-Key", "caller")
	req.Header.Set("Connection", "keep-alive")
	w := httptest.NewRecorder()
	metrics := forwarder.ServeHTTP(w, req, RequestContext{Scheme: "https", Host: "api.example.com", Port: 443}, Evaluation{Outcome: OutcomeAllow, InjectedHeader: http.Header{"X-Api-Key": []string{"injected"}}})
	if w.Code != http.StatusCreated || w.Body.String() != "created" || upstreamHeader != "injected" {
		t.Fatalf("forward code=%d body=%q header=%q", w.Code, w.Body.String(), upstreamHeader)
	}
	if metrics.BytesOut != int64(len("created")) || metrics.UpstreamStatus != http.StatusCreated {
		t.Fatalf("metrics = %+v", metrics)
	}

	var customHopHeader string
	transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		customHopHeader = r.Header.Get("X-Secret-Hop")
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("ok"))}, nil
	})
	forwarder = NewForwarderWithTransport(time.Second, transport)
	req = httptest.NewRequest(http.MethodGet, "http://placeholder.local/resource", nil)
	req.Header.Set("Connection", "X-Secret-Hop")
	req.Header.Set("X-Secret-Hop", "must-not-forward")
	w = httptest.NewRecorder()
	forwarder.ServeHTTP(w, req, RequestContext{Scheme: "https", Host: "api.example.com", Port: 443}, Evaluation{Outcome: OutcomeAllow})
	if customHopHeader != "" {
		t.Fatalf("custom hop-by-hop header reached upstream: %q", customHopHeader)
	}

	upgrade := httptest.NewRequest(http.MethodGet, "http://placeholder.local/socket", nil)
	upgrade.Header.Set("Connection", "upgrade")
	upgrade.Header.Set("Upgrade", "websocket")
	w = httptest.NewRecorder()
	metrics = forwarder.ServeHTTP(w, upgrade, RequestContext{}, Evaluation{Outcome: OutcomeAllow})
	if w.Code != http.StatusUpgradeRequired || metrics.UpstreamStatus != http.StatusUpgradeRequired {
		t.Fatalf("upgrade code=%d metrics=%+v", w.Code, metrics)
	}
}

func TestRuntimeBypassDoesNotProxyOrEmitObservability(t *testing.T) {
	spans := &fakeSpanEmitter{}
	metering := &fakeMeteringClient{}
	rules := NewRuleCache(&fakeRuleClient{rules: [][]*egressv1.EgressRule{{rule("rule-1", "api.example.com", allowEffect())}}}, time.Minute, &fakeClock{now: time.Now()})
	runtime := NewRuntime(rules, NewEvaluator(NewSecretCache(&fakeSecretClient{}, time.Minute, &fakeClock{now: time.Now()})), NewForwarderWithTransport(time.Second, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		t.Fatal("forwarder should not be called for unmatched destinations")
		return nil, nil
	})), NewObservability(spans, metering, &fakeClock{now: time.Now()}))
	req := httptest.NewRequest(http.MethodGet, "http://placeholder.local/v1", nil)
	w := httptest.NewRecorder()
	err := runtime.ServeRequest(context.Background(), w, req, RequestContext{Method: http.MethodGet, Scheme: "https", Host: "unmatched.example.com", Port: 443, Path: "/v1"})
	if err != nil {
		t.Fatalf("ServeRequest: %v", err)
	}
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d", w.Code)
	}
	if len(spans.spans) != 0 || len(metering.requests) != 0 {
		t.Fatalf("observability emitted spans=%d metering=%d", len(spans.spans), len(metering.requests))
	}
}

func TestLeafCertificateCacheGeneratesAndCaches(t *testing.T) {
	clock := &fakeClock{now: time.Unix(200, 0)}
	ca := testCA(t)
	cache := NewLeafCertificateCache(ca, time.Minute, 2, clock)
	first, err := cache.Certificate("api.example.com")
	if err != nil {
		t.Fatalf("Certificate first: %v", err)
	}
	second, err := cache.Certificate("api.example.com")
	if err != nil {
		t.Fatalf("Certificate second: %v", err)
	}
	if first != second {
		t.Fatal("expected cached certificate pointer")
	}
	leaf, err := x509.ParseCertificate(first.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if leaf.DNSNames[0] != "api.example.com" {
		t.Fatalf("dns names = %v", leaf.DNSNames)
	}
	clock.now = clock.now.Add(time.Minute)
	third, err := cache.Certificate("api.example.com")
	if err != nil {
		t.Fatalf("Certificate third: %v", err)
	}
	if third == first {
		t.Fatal("expected regenerated certificate after ttl")
	}
}

func TestOTLPSpanEmitterExportsSpan(t *testing.T) {
	client := &fakeOTLPTraceClient{}
	emitter := NewOTLPSpanEmitter(client)
	span := Span{
		Name:         "egress.request",
		Kind:         "CLIENT",
		StatusCode:   "OK",
		Organization: "org-1",
		StartTime:    time.Unix(10, 0),
		EndTime:      time.Unix(11, 0),
		Attributes: map[string]any{
			"egress.host": "api.example.com",
			"egress.port": 443,
		},
	}
	if err := emitter.EmitSpan(context.Background(), span); err != nil {
		t.Fatalf("EmitSpan: %v", err)
	}
	if len(client.requests) != 1 {
		t.Fatalf("export requests = %d", len(client.requests))
	}
	spans := client.requests[0].GetResourceSpans()[0].GetScopeSpans()[0].GetSpans()
	if len(spans) != 1 || spans[0].GetName() != "egress.request" || spans[0].GetKind() != tracev1.Span_SPAN_KIND_CLIENT {
		t.Fatalf("exported spans = %+v", spans)
	}
}

func TestObservabilityOmitsSensitiveValues(t *testing.T) {
	spans := &fakeSpanEmitter{}
	metering := &fakeMeteringClient{}
	obs := NewObservability(spans, metering, &fakeClock{now: time.Unix(300, 0)})
	metrics := RequestMetrics{
		Context: RequestContext{Agent: AgentContext{AgentID: "agent-1", WorkloadID: "workload-1", OrganizationID: "org-1"}, Method: http.MethodGet, Host: "api.example.com", Port: 443, Path: "/v1", RequestID: "request-1"},
		Outcome: OutcomeAllow, MatchedRuleIDs: []string{"rule-1"}, UpstreamStatus: 200, BytesIn: 10, BytesOut: 20,
	}
	if err := obs.Emit(context.Background(), metrics); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if len(spans.spans) != 1 || len(metering.requests) != 1 {
		t.Fatalf("spans=%d metering=%d", len(spans.spans), len(metering.requests))
	}
	span := spans.spans[0]
	for key := range span.Attributes {
		if strings.Contains(strings.ToLower(key), "authorization") || strings.Contains(strings.ToLower(key), "secret") {
			t.Fatalf("sensitive span key %q", key)
		}
	}
	record := metering.requests[0].GetRecords()[0]
	if record.GetLabels()["resource"] != "egress" || record.GetLabels()["host"] != "api.example.com" || record.GetUnit() != meteringv1.Unit_UNIT_COUNT {
		t.Fatalf("record = %+v", record)
	}
}

func TestObservabilityReturnsEmissionErrors(t *testing.T) {
	spans := &fakeSpanEmitter{err: errors.New("trace down")}
	metering := &fakeMeteringClient{err: errors.New("metering down")}
	obs := NewObservability(spans, metering, &fakeClock{now: time.Unix(300, 0)})
	metrics := RequestMetrics{
		Context: RequestContext{Agent: AgentContext{AgentID: "agent-1", WorkloadID: "workload-1", OrganizationID: "org-1"}, Method: http.MethodGet, Host: "api.example.com", Port: 443, Path: "/v1", RequestID: "request-1"},
		Outcome: OutcomeAllow, MatchedRuleIDs: []string{"rule-1"}, UpstreamStatus: 200, BytesIn: 10, BytesOut: 20,
	}
	err := obs.Emit(context.Background(), metrics)
	if err == nil {
		t.Fatal("expected observability errors")
	}
	if !strings.Contains(err.Error(), "trace down") || !strings.Contains(err.Error(), "metering down") {
		t.Fatalf("err = %v", err)
	}
}

func TestOriginalDestinationFromHostPort(t *testing.T) {
	host, port, scheme, err := OriginalDestinationFromHostPort("api.example.com:443", "")
	if err != nil {
		t.Fatalf("OriginalDestinationFromHostPort: %v", err)
	}
	if host != "api.example.com" || port != 443 || scheme != "https" {
		t.Fatalf("host=%s port=%d scheme=%s", host, port, scheme)
	}
}

func TestDestinationFromAppData(t *testing.T) {
	appData, err := json.Marshal(map[string]string{"dst_protocol": "tcp", "dst_hostname": "api.example.com", "dst_port": "443"})
	if err != nil {
		t.Fatalf("marshal app data: %v", err)
	}
	destination, err := DestinationFromAppData(appData)
	if err != nil {
		t.Fatalf("DestinationFromAppData: %v", err)
	}
	if destination.Host != "api.example.com" || destination.Port != 443 || destination.Scheme != "https" {
		t.Fatalf("destination = %+v", destination)
	}
}

func TestDataPlaneHTTPPathInjectsSecretHeader(t *testing.T) {
	var upstreamHeader string
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		upstreamHeader = r.Header.Get("Authorization")
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("ok"))}, nil
	})
	rules := NewRuleCache(&fakeRuleClient{rules: [][]*egressv1.EgressRule{{rule("rule-1", "api.example.com", injectEffect(headerSecret("Authorization", "secret-1", egressv1.HeaderAuthScheme_HEADER_AUTH_SCHEME_BEARER)))}}}, time.Minute, &fakeClock{now: time.Now()})
	secrets := NewSecretCache(&fakeSecretClient{values: []string{"token"}}, time.Minute, &fakeClock{now: time.Now()})
	runtime := NewRuntime(rules, NewEvaluator(secrets), NewForwarderWithTransport(time.Second, transport), nil)
	identity := NewIdentityResolver(&fakeZitiIdentityClient{}, &fakeAgentIdentityClient{})
	serverConn, clientConn := net.Pipe()
	listener := &fakeDataPlaneListener{conn: &fakeDataPlaneConn{Conn: serverConn, dialerIdentityID: "ziti-agent-1", appData: []byte(`{"dst_protocol":"tcp","dst_hostname":"api.example.com","dst_port":"80"}`)}}
	server := NewDataPlaneServer(listener, runtime, identity, NewLeafCertificateCache(testCA(t), time.Minute, 2, &fakeClock{now: time.Now()}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.Serve(ctx) }()

	if _, err := clientConn.Write([]byte("GET /v1 HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: caller\r\nConnection: close\r\n\r\n")); err != nil {
		t.Fatalf("write request: %v", err)
	}
	response, err := http.ReadResponse(bufioReader(clientConn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || upstreamHeader != "Bearer token" {
		t.Fatalf("status=%d upstream authorization=%q", response.StatusCode, upstreamHeader)
	}
}

func TestDataPlaneStreamsResponseBody(t *testing.T) {
	writeStarted := make(chan struct{})
	finishResponse := make(chan struct{})
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: &blockingBody{started: writeStarted, release: finishResponse}}, nil
	})
	rules := NewRuleCache(&fakeRuleClient{rules: [][]*egressv1.EgressRule{{rule("rule-1", "api.example.com", allowEffect())}}}, time.Minute, &fakeClock{now: time.Now()})
	runtime := NewRuntime(rules, NewEvaluator(NewSecretCache(&fakeSecretClient{}, time.Minute, &fakeClock{now: time.Now()})), NewForwarderWithTransport(time.Second, transport), nil)
	identity := NewIdentityResolver(&fakeZitiIdentityClient{}, &fakeAgentIdentityClient{})
	serverConn, clientConn := net.Pipe()
	listener := &fakeDataPlaneListener{conn: &fakeDataPlaneConn{Conn: serverConn, dialerIdentityID: "ziti-agent-1", appData: []byte(`{"dst_protocol":"tcp","dst_hostname":"api.example.com","dst_port":"80"}`)}}
	server := NewDataPlaneServer(listener, runtime, identity, NewLeafCertificateCache(testCA(t), time.Minute, 2, &fakeClock{now: time.Now()}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.Serve(ctx) }()

	if _, err := clientConn.Write([]byte("GET /stream HTTP/1.1\r\nHost: api.example.com\r\nConnection: close\r\n\r\n")); err != nil {
		t.Fatalf("write request: %v", err)
	}
	reader := bufioReader(clientConn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read status line: %v", err)
	}
	if !strings.Contains(statusLine, "200 OK") {
		t.Fatalf("status line = %q", statusLine)
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read header line: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}
	bodyBytes := make(chan []byte, 1)
	go func() {
		buf := make([]byte, len("chunk"))
		_, _ = io.ReadFull(reader, buf)
		bodyBytes <- buf
	}()
	select {
	case body := <-bodyBytes:
		if string(body) != "chunk" {
			t.Errorf("streamed body = %q", string(body))
		}
	case <-time.After(time.Second):
		t.Fatal("response body was not streamed before upstream completion")
	}
	<-writeStarted
	close(finishResponse)
}

func TestDataPlaneRuntimeErrorDoesNotWriteDefaultSuccess(t *testing.T) {
	rules := NewRuleCache(&fakeRuleClient{errors: []error{errors.New("rules down")}}, time.Minute, &fakeClock{now: time.Now()})
	runtime := NewRuntime(rules, NewEvaluator(NewSecretCache(&fakeSecretClient{}, time.Minute, &fakeClock{now: time.Now()})), NewForwarderWithTransport(time.Second, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		t.Fatal("forwarder should not be called when rules fail")
		return nil, nil
	})), nil)
	identity := NewIdentityResolver(&fakeZitiIdentityClient{}, &fakeAgentIdentityClient{})
	serverConn, clientConn := net.Pipe()
	listener := &fakeDataPlaneListener{conn: &fakeDataPlaneConn{Conn: serverConn, dialerIdentityID: "ziti-agent-1", appData: []byte(`{"dst_protocol":"tcp","dst_hostname":"api.example.com","dst_port":"80"}`)}}
	server := NewDataPlaneServer(listener, runtime, identity, NewLeafCertificateCache(testCA(t), time.Minute, 2, &fakeClock{now: time.Now()}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.Serve(ctx) }()

	if _, err := clientConn.Write([]byte("GET /v1 HTTP/1.1\r\nHost: api.example.com\r\nConnection: close\r\n\r\n")); err != nil {
		t.Fatalf("write request: %v", err)
	}
	response, err := http.ReadResponse(bufioReader(clientConn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d", response.StatusCode)
	}
}

func TestDefaultZitiBindingDiscoversRoleServices(t *testing.T) {
	services := []rest_model.ServiceDetail{
		serviceDetail("egress-rule-1", "egress-services"),
		serviceDetail("ordinary-service", "not-egress"),
	}
	zitiCtx := &fakeZitiContext{services: services, listeners: map[string]*fakeEdgeListener{}}
	listener, err := ListenForEgressServices(zitiCtx, "")
	if err != nil {
		t.Fatalf("ListenForEgressServices: %v", err)
	}
	defer listener.Close()
	waitForListen(t, zitiCtx, "egress-rule-1")
	if zitiCtx.listened("#egress-services") {
		t.Fatal("default binding passed literal role selector to SDK")
	}
	if zitiCtx.listened("ordinary-service") {
		t.Fatal("default binding listened to service without egress role")
	}
}

func TestServiceRoleListenerReconcilesAddedServices(t *testing.T) {
	zitiCtx := &fakeZitiContext{listeners: map[string]*fakeEdgeListener{}}
	listener := NewServiceRoleListenerWithInterval(zitiCtx, "egress-services", time.Millisecond)
	defer listener.Close()
	if zitiCtx.listened("#egress-services") {
		t.Fatal("role reconciler passed literal selector to SDK")
	}
	zitiCtx.setServices([]rest_model.ServiceDetail{serviceDetail("egress-rule-2", "egress-services")})
	waitForListen(t, zitiCtx, "egress-rule-2")
}

func TestDataPlaneHTTPSUsesGeneratedLeafCertificate(t *testing.T) {
	var upstreamHost string
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		upstreamHost = r.URL.Host
		return &http.Response{StatusCode: http.StatusAccepted, Body: io.NopCloser(strings.NewReader("accepted"))}, nil
	})
	rules := NewRuleCache(&fakeRuleClient{rules: [][]*egressv1.EgressRule{{rule("rule-1", "api.example.com", allowEffect())}}}, time.Minute, &fakeClock{now: time.Now()})
	runtime := NewRuntime(rules, NewEvaluator(NewSecretCache(&fakeSecretClient{}, time.Minute, &fakeClock{now: time.Now()})), NewForwarderWithTransport(time.Second, transport), nil)
	identity := NewIdentityResolver(&fakeZitiIdentityClient{}, &fakeAgentIdentityClient{})
	serverConn, clientConn := net.Pipe()
	ca := testCA(t)
	listener := &fakeDataPlaneListener{conn: &fakeDataPlaneConn{Conn: serverConn, dialerIdentityID: "ziti-agent-1", appData: []byte(`{"dst_protocol":"tcp","dst_hostname":"api.example.com","dst_port":"443"}`)}}
	server := NewDataPlaneServer(listener, runtime, identity, NewLeafCertificateCache(ca, time.Minute, 2, &fakeClock{now: time.Now()}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.Serve(ctx) }()

	root := x509.NewCertPool()
	root.AddCert(ca.cert)
	tlsClient := tls.Client(clientConn, &tls.Config{ServerName: "api.example.com", RootCAs: root})
	if _, err := tlsClient.Write([]byte("GET /secure HTTP/1.1\r\nHost: api.example.com\r\nConnection: close\r\n\r\n")); err != nil {
		t.Fatalf("write tls request: %v", err)
	}
	response, err := http.ReadResponse(bufioReader(tlsClient), nil)
	if err != nil {
		t.Fatalf("read tls response: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusAccepted || upstreamHost != "api.example.com:443" {
		t.Fatalf("status=%d upstream host=%q", response.StatusCode, upstreamHost)
	}
}

func TestDataPlaneHTTP2PathInjectsSecretHeader(t *testing.T) {
	var upstreamHeader string
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		upstreamHeader = r.Header.Get("Authorization")
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("ok"))}, nil
	})
	rules := NewRuleCache(&fakeRuleClient{rules: [][]*egressv1.EgressRule{{rule("rule-1", "api.example.com", injectEffect(headerSecret("Authorization", "secret-1", egressv1.HeaderAuthScheme_HEADER_AUTH_SCHEME_BEARER)))}}}, time.Minute, &fakeClock{now: time.Now()})
	secrets := NewSecretCache(&fakeSecretClient{values: []string{"token"}}, time.Minute, &fakeClock{now: time.Now()})
	runtime := NewRuntime(rules, NewEvaluator(secrets), NewForwarderWithTransport(time.Second, transport), nil)
	identity := NewIdentityResolver(&fakeZitiIdentityClient{}, &fakeAgentIdentityClient{})
	serverConn, clientConn := net.Pipe()
	ca := testCA(t)
	listener := &fakeDataPlaneListener{conn: &fakeDataPlaneConn{Conn: serverConn, dialerIdentityID: "ziti-agent-1", appData: []byte(`{"dst_protocol":"tcp","dst_hostname":"api.example.com","dst_port":"443"}`)}}
	server := NewDataPlaneServer(listener, runtime, identity, NewLeafCertificateCache(ca, time.Minute, 2, &fakeClock{now: time.Now()}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.Serve(ctx) }()

	root := x509.NewCertPool()
	root.AddCert(ca.cert)
	h2Client := &http.Client{Transport: &http2.Transport{DialTLSContext: func(context.Context, string, string, *tls.Config) (net.Conn, error) {
		return tls.Client(clientConn, &tls.Config{ServerName: "api.example.com", RootCAs: root, NextProtos: []string{"h2"}}), nil
	}}}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.example.com/secure", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	request.Header.Set("Authorization", "caller")
	response, err := h2Client.Do(request)
	if err != nil {
		t.Fatalf("h2 request: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || upstreamHeader != "Bearer token" {
		t.Fatalf("status=%d upstream authorization=%q", response.StatusCode, upstreamHeader)
	}
}

type fakeClock struct{ now time.Time }

func (f *fakeClock) Now() time.Time { return f.now }

type fakeRuleClient struct {
	rules  [][]*egressv1.EgressRule
	errors []error
	calls  int
}

func (f *fakeRuleClient) ListEgressRulesByAgent(context.Context, *egressv1.ListEgressRulesByAgentRequest, ...grpc.CallOption) (*egressv1.ListEgressRulesByAgentResponse, error) {
	index := f.calls
	f.calls++
	if index < len(f.errors) && f.errors[index] != nil {
		return nil, f.errors[index]
	}
	return &egressv1.ListEgressRulesByAgentResponse{EgressRules: f.rules[index]}, nil
}

type fakeSecretClient struct {
	values []string
	calls  int
}

func (f *fakeSecretClient) ResolveSecret(context.Context, *secretsv1.ResolveSecretRequest, ...grpc.CallOption) (*secretsv1.ResolveSecretResponse, error) {
	value := ""
	if f.calls < len(f.values) {
		value = f.values[f.calls]
	}
	f.calls++
	return &secretsv1.ResolveSecretResponse{Value: value}, nil
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type fakeSpanEmitter struct {
	spans []Span
	err   error
}

func (f *fakeSpanEmitter) EmitSpan(_ context.Context, span Span) error {
	if f.err != nil {
		return f.err
	}
	f.spans = append(f.spans, span)
	return nil
}

type fakeMeteringClient struct {
	requests []*meteringv1.RecordRequest
	err      error
}

func (f *fakeMeteringClient) Record(_ context.Context, req *meteringv1.RecordRequest, _ ...grpc.CallOption) (*meteringv1.RecordResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.requests = append(f.requests, req)
	return &meteringv1.RecordResponse{}, nil
}

type fakeOTLPTraceClient struct {
	requests []*collectortracev1.ExportTraceServiceRequest
}

func (f *fakeOTLPTraceClient) Export(_ context.Context, req *collectortracev1.ExportTraceServiceRequest, _ ...grpc.CallOption) (*collectortracev1.ExportTraceServiceResponse, error) {
	f.requests = append(f.requests, req)
	return &collectortracev1.ExportTraceServiceResponse{}, nil
}

type fakeNotificationsClient struct{}

func (f *fakeNotificationsClient) Subscribe(context.Context, *notificationsv1.SubscribeRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[notificationsv1.SubscribeResponse], error) {
	return nil, io.EOF
}

type ruleOption func(*egressv1.EgressRule)

func rule(id string, domain string, effect *egressv1.EgressRuleEffect, options ...ruleOption) *egressv1.EgressRule {
	r := &egressv1.EgressRule{Meta: &egressv1.EntityMeta{Id: id}, Matcher: &egressv1.EgressRuleMatcher{DomainPattern: domain}, Effect: effect}
	for _, option := range options {
		option(r)
	}
	return r
}

func withPorts(ports ...int32) ruleOption {
	return func(rule *egressv1.EgressRule) { rule.Matcher.Ports = ports }
}

func withMethods(methods ...string) ruleOption {
	return func(rule *egressv1.EgressRule) { rule.Matcher.Methods = methods }
}

func withPath(pattern string) ruleOption {
	return func(rule *egressv1.EgressRule) { rule.Matcher.PathPattern = pattern }
}

func allowEffect() *egressv1.EgressRuleEffect {
	return &egressv1.EgressRuleEffect{Action: egressv1.EgressRuleAction_EGRESS_RULE_ACTION_ALLOW.Enum()}
}

func denyEffect() *egressv1.EgressRuleEffect {
	return &egressv1.EgressRuleEffect{Action: egressv1.EgressRuleAction_EGRESS_RULE_ACTION_DENY.Enum()}
}

func injectEffect(headers ...*egressv1.EgressRuleHeader) *egressv1.EgressRuleEffect {
	return &egressv1.EgressRuleEffect{Inject: headers}
}

func headerValue(name string, value string) *egressv1.EgressRuleHeader {
	return &egressv1.EgressRuleHeader{Name: name, Credential: &egressv1.EgressRuleHeader_Value{Value: value}}
}

func headerSecret(name string, secretID string, scheme egressv1.HeaderAuthScheme) *egressv1.EgressRuleHeader {
	return &egressv1.EgressRuleHeader{Name: name, Scheme: scheme, Credential: &egressv1.EgressRuleHeader_SecretId{SecretId: secretID}}
}

func testCA(t *testing.T) *CertificateAuthority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ca key: %v", err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test ca"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatalf("create ca cert: %v", err)
	}
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal ca key: %v", err)
	}
	certFile := tempPEM(t, "CERTIFICATE", der)
	keyFile := tempPEM(t, "PRIVATE KEY", keyBytes)
	ca, err := LoadCertificateAuthority(certFile, keyFile)
	if err != nil {
		t.Fatalf("LoadCertificateAuthority: %v", err)
	}
	return ca
}

func tempPEM(t *testing.T, blockType string, der []byte) string {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "pem-*")
	if err != nil {
		t.Fatalf("create temp pem: %v", err)
	}
	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		t.Fatalf("encode pem: %v", err)
	}
	if _, err := file.Write(buf.Bytes()); err != nil {
		t.Fatalf("write pem: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close pem: %v", err)
	}
	return file.Name()
}

type fakeZitiIdentityClient struct{}

func (f *fakeZitiIdentityClient) ResolveIdentity(context.Context, *zitimanagementv1.ResolveIdentityRequest, ...grpc.CallOption) (*zitimanagementv1.ResolveIdentityResponse, error) {
	return &zitimanagementv1.ResolveIdentityResponse{IdentityId: "identity-1", IdentityType: identityv1.IdentityType_IDENTITY_TYPE_AGENT, WorkloadId: stringPtr("workload-1")}, nil
}

type fakeAgentIdentityClient struct{}

func (f *fakeAgentIdentityClient) ResolveAgentIdentity(context.Context, *agentsv1.ResolveAgentIdentityRequest, ...grpc.CallOption) (*agentsv1.ResolveAgentIdentityResponse, error) {
	return &agentsv1.ResolveAgentIdentityResponse{AgentId: "agent-1", OrganizationId: "org-1"}, nil
}

type fakeZitiContext struct {
	mu        sync.Mutex
	services  []rest_model.ServiceDetail
	listeners map[string]*fakeEdgeListener
}

func (f *fakeZitiContext) Authenticate() error { return nil }

func (f *fakeZitiContext) RefreshServices() error { return nil }

func (f *fakeZitiContext) GetServices() ([]rest_model.ServiceDetail, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	services := make([]rest_model.ServiceDetail, len(f.services))
	copy(services, f.services)
	return services, nil
}

func (f *fakeZitiContext) ListenWithOptions(serviceName string, _ *ziti.ListenOptions) (edge.Listener, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listeners == nil {
		f.listeners = map[string]*fakeEdgeListener{}
	}
	listener := &fakeEdgeListener{serviceName: serviceName, closed: make(chan struct{})}
	f.listeners[serviceName] = listener
	return listener, nil
}

func (f *fakeZitiContext) Close() {}

func (f *fakeZitiContext) setServices(services []rest_model.ServiceDetail) {
	f.mu.Lock()
	f.services = services
	f.mu.Unlock()
}

func (f *fakeZitiContext) listened(serviceName string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.listeners[serviceName]
	return ok
}

type fakeEdgeListener struct {
	serviceName string
	closed      chan struct{}
}

func (f *fakeEdgeListener) Accept() (net.Conn, error) {
	<-f.closed
	return nil, net.ErrClosed
}

func (f *fakeEdgeListener) AcceptEdge() (edge.Conn, error) {
	<-f.closed
	return nil, net.ErrClosed
}

func (f *fakeEdgeListener) Close() error {
	select {
	case <-f.closed:
	default:
		close(f.closed)
	}
	return nil
}

func (f *fakeEdgeListener) Addr() net.Addr { return &net.TCPAddr{} }

func (f *fakeEdgeListener) Id() uint32 { return 0 }

func (f *fakeEdgeListener) IsClosed() bool {
	select {
	case <-f.closed:
		return true
	default:
		return false
	}
}

func (f *fakeEdgeListener) UpdateCost(uint16) error { return nil }

func (f *fakeEdgeListener) UpdatePrecedence(edge.Precedence) error { return nil }

func (f *fakeEdgeListener) UpdateCostAndPrecedence(uint16, edge.Precedence) error { return nil }

func (f *fakeEdgeListener) SendHealthEvent(bool) error { return nil }

type fakeDataPlaneListener struct {
	conn   DataPlaneConn
	closed chan struct{}
	taken  bool
}

func (f *fakeDataPlaneListener) Accept() (DataPlaneConn, error) {
	if f.closed == nil {
		f.closed = make(chan struct{})
	}
	if !f.taken {
		f.taken = true
		return f.conn, nil
	}
	<-f.closed
	return nil, net.ErrClosed
}

func (f *fakeDataPlaneListener) Close() error {
	if f.closed == nil {
		f.closed = make(chan struct{})
	}
	select {
	case <-f.closed:
	default:
		close(f.closed)
	}
	return nil
}

type fakeDataPlaneConn struct {
	net.Conn
	dialerIdentityID string
	appData          []byte
}

func (f *fakeDataPlaneConn) DialerIdentityID() string { return f.dialerIdentityID }

func (f *fakeDataPlaneConn) AppData() []byte { return f.appData }

func stringPtr(value string) *string { return &value }

func bufioReader(conn net.Conn) *bufio.Reader { return bufio.NewReader(conn) }

func serviceDetail(name string, roles ...string) rest_model.ServiceDetail {
	attributes := rest_model.Attributes(roles)
	return rest_model.ServiceDetail{Name: &name, RoleAttributes: &attributes}
}

func waitForListen(t *testing.T, zitiCtx *fakeZitiContext, serviceName string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if zitiCtx.listened(serviceName) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("service %q was not listened", serviceName)
}

type blockingBody struct {
	started chan struct{}
	release chan struct{}
	sent    bool
}

func (b *blockingBody) Read(p []byte) (int, error) {
	if b.sent {
		<-b.release
		return 0, io.EOF
	}
	b.sent = true
	copy(p, "chunk")
	close(b.started)
	return len("chunk"), nil
}

func (b *blockingBody) Close() error { return nil }

var _ = timestamppb.Now
