package egress

import (
	"context"
	"crypto/rand"
	"fmt"
	"time"

	collectortracev1 "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonv1 "go.opentelemetry.io/proto/otlp/common/v1"
	resourcev1 "go.opentelemetry.io/proto/otlp/resource/v1"
	tracev1 "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/grpc"
)

type OTLPTraceClient interface {
	Export(context.Context, *collectortracev1.ExportTraceServiceRequest, ...grpc.CallOption) (*collectortracev1.ExportTraceServiceResponse, error)
}

type OTLPSpanEmitter struct {
	client OTLPTraceClient
}

func NewOTLPSpanEmitter(client OTLPTraceClient) *OTLPSpanEmitter {
	if client == nil {
		panic("trace client is required")
	}
	return &OTLPSpanEmitter{client: client}
}

func (e *OTLPSpanEmitter) EmitSpan(ctx context.Context, span Span) error {
	traceID, err := randomTraceBytes(16)
	if err != nil {
		return err
	}
	spanID, err := randomTraceBytes(8)
	if err != nil {
		return err
	}
	otelSpan, err := otlpSpan(span, traceID, spanID)
	if err != nil {
		return err
	}
	_, err = e.client.Export(ctx, &collectortracev1.ExportTraceServiceRequest{ResourceSpans: []*tracev1.ResourceSpans{{
		Resource: &resourcev1.Resource{Attributes: []*commonv1.KeyValue{
			stringKeyValue("service.name", "egress-gateway"),
			stringKeyValue("agyn.organization.id", span.Organization),
		}},
		ScopeSpans: []*tracev1.ScopeSpans{{Spans: []*tracev1.Span{otelSpan}}},
	}}})
	if err != nil {
		return fmt.Errorf("export otlp span: %w", err)
	}
	return nil
}

func otlpSpan(span Span, traceID []byte, spanID []byte) (*tracev1.Span, error) {
	attrs, err := otlpAttributes(span.Attributes)
	if err != nil {
		return nil, err
	}
	return &tracev1.Span{
		TraceId:           traceID,
		SpanId:            spanID,
		Name:              span.Name,
		Kind:              otlpSpanKind(span.Kind),
		StartTimeUnixNano: uint64(traceTime(span.StartTime).UnixNano()),
		EndTimeUnixNano:   uint64(traceTime(span.EndTime).UnixNano()),
		Attributes:        attrs,
		Status:            &tracev1.Status{Code: otlpStatusCode(span.StatusCode)},
	}, nil
}

func otlpAttributes(attributes map[string]any) ([]*commonv1.KeyValue, error) {
	attrs := make([]*commonv1.KeyValue, 0, len(attributes))
	for key, value := range attributes {
		switch typed := value.(type) {
		case string:
			attrs = append(attrs, stringKeyValue(key, typed))
		case int:
			attrs = append(attrs, intKeyValue(key, int64(typed)))
		case int64:
			attrs = append(attrs, intKeyValue(key, typed))
		case bool:
			attrs = append(attrs, boolKeyValue(key, typed))
		default:
			return nil, fmt.Errorf("unsupported span attribute %s type %T", key, value)
		}
	}
	return attrs, nil
}

func stringKeyValue(key string, value string) *commonv1.KeyValue {
	return &commonv1.KeyValue{Key: key, Value: &commonv1.AnyValue{Value: &commonv1.AnyValue_StringValue{StringValue: value}}}
}

func intKeyValue(key string, value int64) *commonv1.KeyValue {
	return &commonv1.KeyValue{Key: key, Value: &commonv1.AnyValue{Value: &commonv1.AnyValue_IntValue{IntValue: value}}}
}

func boolKeyValue(key string, value bool) *commonv1.KeyValue {
	return &commonv1.KeyValue{Key: key, Value: &commonv1.AnyValue{Value: &commonv1.AnyValue_BoolValue{BoolValue: value}}}
}

func otlpSpanKind(kind string) tracev1.Span_SpanKind {
	switch kind {
	case "CLIENT":
		return tracev1.Span_SPAN_KIND_CLIENT
	case "":
		return tracev1.Span_SPAN_KIND_UNSPECIFIED
	default:
		panic("unsupported span kind " + kind)
	}
}

func otlpStatusCode(statusCode string) tracev1.Status_StatusCode {
	switch statusCode {
	case "OK":
		return tracev1.Status_STATUS_CODE_OK
	case "ERROR":
		return tracev1.Status_STATUS_CODE_ERROR
	case "":
		return tracev1.Status_STATUS_CODE_UNSET
	default:
		panic("unsupported span status code " + statusCode)
	}
}

func traceTime(value time.Time) time.Time {
	if value.IsZero() {
		return time.Now()
	}
	return value
}

func randomTraceBytes(size int) ([]byte, error) {
	bytes := make([]byte, size)
	if _, err := rand.Read(bytes); err != nil {
		return nil, fmt.Errorf("generate trace id: %w", err)
	}
	return bytes, nil
}
