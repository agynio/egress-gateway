package egress

import (
	"context"
	egressv1 "github.com/agynio/egress-gateway/.gen/go/agynio/api/egress/v1"
	"strings"
	"time"

	meteringv1 "github.com/agynio/egress-gateway/.gen/go/agynio/api/metering/v1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Span struct {
	Name       string
	Kind       string
	StatusCode string
	Attributes map[string]any
}

type SpanEmitter interface {
	EmitSpan(context.Context, Span) error
}

type MeteringClient interface {
	Record(context.Context, *meteringv1.RecordRequest, ...grpc.CallOption) (*meteringv1.RecordResponse, error)
}

type Observability struct {
	spans    SpanEmitter
	metering MeteringClient
	clock    Clock
}

func NewObservability(spans SpanEmitter, metering MeteringClient, clock Clock) *Observability {
	if clock == nil {
		panic("clock is required")
	}
	return &Observability{spans: spans, metering: metering, clock: clock}
}

func (o *Observability) Emit(ctx context.Context, metrics RequestMetrics) {
	if o.spans != nil {
		_ = o.spans.EmitSpan(ctx, spanFromMetrics(metrics))
	}
	if o.metering != nil {
		_, _ = o.metering.Record(ctx, &meteringv1.RecordRequest{Records: []*meteringv1.UsageRecord{meteringRecordFromMetrics(metrics, o.clock.Now())}})
	}
}

func spanFromMetrics(metrics RequestMetrics) Span {
	statusCode := "OK"
	if metrics.Outcome == OutcomeUpstreamError || metrics.Outcome == OutcomeTLSError {
		statusCode = "ERROR"
	}
	attributes := map[string]any{
		"egress.method":           metrics.Context.Method,
		"egress.host":             metrics.Context.Host,
		"egress.port":             metrics.Context.Port,
		"egress.path":             metrics.Context.Path,
		"egress.outcome":          string(metrics.Outcome),
		"egress.matched_rule_ids": strings.Join(metrics.MatchedRuleIDs, ","),
		"egress.bytes_in":         metrics.BytesIn,
		"egress.bytes_out":        metrics.BytesOut,
		"agyn.agent.id":           metrics.Context.Agent.AgentID,
		"agyn.workload.id":        metrics.Context.Agent.WorkloadID,
		"agyn.organization.id":    metrics.Context.Agent.OrganizationID,
	}
	if metrics.UpstreamStatus != 0 {
		attributes["egress.upstream_status"] = metrics.UpstreamStatus
	}
	return Span{Name: "egress.request", Kind: "CLIENT", StatusCode: statusCode, Attributes: attributes}
}

func meteringRecordFromMetrics(metrics RequestMetrics, now time.Time) *meteringv1.UsageRecord {
	return &meteringv1.UsageRecord{
		OrgId:          metrics.Context.Agent.OrganizationID,
		IdempotencyKey: metrics.Context.RequestID,
		Producer:       "egress-gateway",
		Timestamp:      timestamppb.New(now),
		Labels: map[string]string{
			"resource": "egress",
			"agent_id": metrics.Context.Agent.AgentID,
			"host":     metrics.Context.Host,
			"outcome":  string(metrics.Outcome),
		},
		Unit:  meteringv1.Unit_UNIT_COUNT,
		Value: 1,
	}
}

func matchedRuleIDs(rules []*egressv1.EgressRule) []string {
	ids := make([]string, 0, len(rules))
	for _, rule := range rules {
		ids = append(ids, rule.GetMeta().GetId())
	}
	return ids
}
