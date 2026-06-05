package egress

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	egressv1 "github.com/agynio/egress-gateway/.gen/go/agynio/api/egress/v1"
	meteringv1 "github.com/agynio/egress-gateway/.gen/go/agynio/api/metering/v1"
	secretsv1 "github.com/agynio/egress-gateway/.gen/go/agynio/api/secrets/v1"
	"google.golang.org/grpc"
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

	upgrade := httptest.NewRequest(http.MethodGet, "http://placeholder.local/socket", nil)
	upgrade.Header.Set("Connection", "upgrade")
	upgrade.Header.Set("Upgrade", "websocket")
	w = httptest.NewRecorder()
	metrics = forwarder.ServeHTTP(w, upgrade, RequestContext{}, Evaluation{Outcome: OutcomeAllow})
	if w.Code != http.StatusUpgradeRequired || metrics.UpstreamStatus != http.StatusUpgradeRequired {
		t.Fatalf("upgrade code=%d metrics=%+v", w.Code, metrics)
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

func TestObservabilityOmitsSensitiveValues(t *testing.T) {
	spans := &fakeSpanEmitter{}
	metering := &fakeMeteringClient{}
	obs := NewObservability(spans, metering, &fakeClock{now: time.Unix(300, 0)})
	metrics := RequestMetrics{
		Context: RequestContext{Agent: AgentContext{AgentID: "agent-1", WorkloadID: "workload-1", OrganizationID: "org-1"}, Method: http.MethodGet, Host: "api.example.com", Port: 443, Path: "/v1", RequestID: "request-1"},
		Outcome: OutcomeAllow, MatchedRuleIDs: []string{"rule-1"}, UpstreamStatus: 200, BytesIn: 10, BytesOut: 20,
	}
	obs.Emit(context.Background(), metrics)
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

func TestOriginalDestinationFromHostPort(t *testing.T) {
	host, port, scheme, err := OriginalDestinationFromHostPort("api.example.com:443", "")
	if err != nil {
		t.Fatalf("OriginalDestinationFromHostPort: %v", err)
	}
	if host != "api.example.com" || port != 443 || scheme != "https" {
		t.Fatalf("host=%s port=%d scheme=%s", host, port, scheme)
	}
}

type fakeClock struct{ now time.Time }

func (f *fakeClock) Now() time.Time { return f.now }

type fakeRuleClient struct {
	rules [][]*egressv1.EgressRule
	calls int
}

func (f *fakeRuleClient) ListEgressRulesByAgent(context.Context, *egressv1.ListEgressRulesByAgentRequest, ...grpc.CallOption) (*egressv1.ListEgressRulesByAgentResponse, error) {
	index := f.calls
	f.calls++
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

type fakeSpanEmitter struct{ spans []Span }

func (f *fakeSpanEmitter) EmitSpan(_ context.Context, span Span) error {
	f.spans = append(f.spans, span)
	return nil
}

type fakeMeteringClient struct{ requests []*meteringv1.RecordRequest }

func (f *fakeMeteringClient) Record(_ context.Context, req *meteringv1.RecordRequest, _ ...grpc.CallOption) (*meteringv1.RecordResponse, error) {
	f.requests = append(f.requests, req)
	return &meteringv1.RecordResponse{}, nil
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

var _ = timestamppb.Now
