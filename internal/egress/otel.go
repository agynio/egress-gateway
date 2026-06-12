package egress

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

type OTelSpanEmitter struct {
	tracer trace.Tracer
}

func NewOTelSpanEmitter(tracer trace.Tracer) *OTelSpanEmitter {
	if tracer == nil {
		panic("tracer is required")
	}
	return &OTelSpanEmitter{tracer: tracer}
}

func (e *OTelSpanEmitter) EmitSpan(ctx context.Context, span Span) error {
	attrs, err := spanAttributes(span.Attributes)
	if err != nil {
		return err
	}
	_, otelSpan := e.tracer.Start(ctx, span.Name, trace.WithSpanKind(trace.SpanKindClient), trace.WithAttributes(attrs...))
	defer otelSpan.End()
	otelSpan.SetStatus(otelStatus(span.StatusCode), "")
	return nil
}

func spanAttributes(attributes map[string]any) ([]attribute.KeyValue, error) {
	attrs := make([]attribute.KeyValue, 0, len(attributes))
	for key, value := range attributes {
		switch typed := value.(type) {
		case string:
			attrs = append(attrs, attribute.String(key, typed))
		case int:
			attrs = append(attrs, attribute.Int(key, typed))
		case int64:
			attrs = append(attrs, attribute.Int64(key, typed))
		case bool:
			attrs = append(attrs, attribute.Bool(key, typed))
		default:
			return nil, fmt.Errorf("unsupported span attribute %s type %T", key, value)
		}
	}
	return attrs, nil
}

func otelStatus(statusCode string) codes.Code {
	switch statusCode {
	case "OK":
		return codes.Ok
	case "ERROR":
		return codes.Error
	case "":
		return codes.Unset
	default:
		panic("unsupported span status code " + statusCode)
	}
}
