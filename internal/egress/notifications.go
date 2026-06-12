package egress

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"time"

	notificationsv1 "github.com/agynio/egress-gateway/.gen/go/agynio/api/notifications/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

const (
	egressRuleUpdatedEvent           = "egress_rule.updated"
	egressRuleAttachmentUpdatedEvent = "egress_rule_attachment.updated"
	EgressRulesRoom                  = "egress_rules"
	identityMetadataKey              = "x-identity-id"
	subscriberIdentityID             = "00000000-0000-0000-0000-000000000000"
	defaultNotificationsBackoff      = time.Second
)

type NotificationsClient interface {
	Subscribe(context.Context, *notificationsv1.SubscribeRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[notificationsv1.SubscribeResponse], error)
}

type RuleInvalidationSubscriber struct {
	client  NotificationsClient
	rules   *RuleCache
	rooms   []string
	backoff time.Duration
}

func NewRuleInvalidationSubscriber(client NotificationsClient, rules *RuleCache, rooms []string) *RuleInvalidationSubscriber {
	if client == nil {
		panic("notifications client is required")
	}
	if rules == nil {
		panic("rule cache is required")
	}
	return &RuleInvalidationSubscriber{client: client, rules: rules, rooms: append([]string(nil), rooms...), backoff: defaultNotificationsBackoff}
}

func (s *RuleInvalidationSubscriber) Run(ctx context.Context) error {
	for ctx.Err() == nil {
		if err := s.runStream(ctx); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			log.Printf("egress rule invalidation stream failed: %v", err)
		}
		if !sleepContext(ctx, s.backoff) {
			return ctx.Err()
		}
	}
	return ctx.Err()
}

func (s *RuleInvalidationSubscriber) runStream(ctx context.Context) error {
	ctx = metadata.AppendToOutgoingContext(ctx, identityMetadataKey, subscriberIdentityID)
	stream, err := s.client.Subscribe(ctx, &notificationsv1.SubscribeRequest{Rooms: s.rooms})
	if err != nil {
		return fmt.Errorf("subscribe egress invalidations: %w", err)
	}
	for {
		resp, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("receive egress invalidation: %w", err)
		}
		envelope := resp.GetEnvelope()
		if envelope == nil {
			continue
		}
		s.handleEnvelope(envelope)
	}
}

func (s *RuleInvalidationSubscriber) handleEnvelope(envelope *notificationsv1.NotificationEnvelope) {
	switch envelope.GetEvent() {
	case egressRuleAttachmentUpdatedEvent:
		agentID := stringPayloadValue(envelope, "agent_id")
		if agentID == "" {
			s.rules.InvalidateAll()
			return
		}
		s.rules.Invalidate(agentID)
	case egressRuleUpdatedEvent:
		s.rules.InvalidateAll()
	}
}

func stringPayloadValue(envelope *notificationsv1.NotificationEnvelope, key string) string {
	payload := envelope.GetPayload()
	if payload == nil {
		return ""
	}
	value := payload.GetFields()[key]
	if value == nil {
		return ""
	}
	return value.GetStringValue()
}

func sleepContext(ctx context.Context, duration time.Duration) bool {
	if duration <= 0 {
		return true
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
