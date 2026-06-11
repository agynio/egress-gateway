package egress

import (
	"context"
	"sync"
	"time"

	egressv1 "github.com/agynio/egress-gateway/.gen/go/agynio/api/egress/v1"
	secretsv1 "github.com/agynio/egress-gateway/.gen/go/agynio/api/secrets/v1"
	"google.golang.org/grpc"
)

type Clock interface {
	Now() time.Time
}

type SystemClock struct{}

func (SystemClock) Now() time.Time { return time.Now() }

type RuleClient interface {
	ListEgressRulesByAgent(context.Context, *egressv1.ListEgressRulesByAgentRequest, ...grpc.CallOption) (*egressv1.ListEgressRulesByAgentResponse, error)
}

type SecretClient interface {
	ResolveSecret(context.Context, *secretsv1.ResolveSecretRequest, ...grpc.CallOption) (*secretsv1.ResolveSecretResponse, error)
}

type RuleCache struct {
	client         RuleClient
	clock          Clock
	ttl            time.Duration
	staleIfError   time.Duration
	failureHandler func(string, error)
	mu             sync.Mutex
	items          map[string]ruleCacheEntry
}

type ruleCacheEntry struct {
	rules     []*egressv1.EgressRule
	expiresAt time.Time
}

func NewRuleCache(client RuleClient, ttl time.Duration, clock Clock) *RuleCache {
	return NewRuleCacheWithStaleIfError(client, ttl, ttl, clock, nil)
}

func NewRuleCacheWithStaleIfError(client RuleClient, ttl time.Duration, staleIfError time.Duration, clock Clock, failureHandler func(string, error)) *RuleCache {
	if ttl <= 0 {
		panic("rule cache ttl must be positive")
	}
	if staleIfError < 0 {
		panic("rule cache stale-if-error must not be negative")
	}
	if clock == nil {
		panic("clock is required")
	}
	return &RuleCache{client: client, ttl: ttl, staleIfError: staleIfError, clock: clock, failureHandler: failureHandler, items: map[string]ruleCacheEntry{}}
}

func (c *RuleCache) Rules(ctx context.Context, agentID string) ([]*egressv1.EgressRule, error) {
	now := c.clock.Now()
	c.mu.Lock()
	entry, ok := c.items[agentID]
	if ok && now.Before(entry.expiresAt) {
		rules := cloneRules(entry.rules)
		c.mu.Unlock()
		return rules, nil
	}
	c.mu.Unlock()

	resp, err := c.client.ListEgressRulesByAgent(ctx, &egressv1.ListEgressRulesByAgentRequest{AgentId: agentID})
	if err != nil {
		if ok && !now.After(entry.expiresAt.Add(c.staleIfError)) {
			if c.failureHandler != nil {
				c.failureHandler(agentID, err)
			}
			return cloneRules(entry.rules), nil
		}
		return nil, err
	}
	rules := cloneRules(resp.GetEgressRules())
	c.mu.Lock()
	c.items[agentID] = ruleCacheEntry{rules: cloneRules(rules), expiresAt: c.clock.Now().Add(c.ttl)}
	c.mu.Unlock()
	return rules, nil
}

func (c *RuleCache) Invalidate(agentID string) {
	c.mu.Lock()
	delete(c.items, agentID)
	c.mu.Unlock()
}

func (c *RuleCache) InvalidateAll() {
	c.mu.Lock()
	c.items = map[string]ruleCacheEntry{}
	c.mu.Unlock()
}

func cloneRules(rules []*egressv1.EgressRule) []*egressv1.EgressRule {
	cloned := make([]*egressv1.EgressRule, len(rules))
	copy(cloned, rules)
	return cloned
}

type SecretCache struct {
	client SecretClient
	clock  Clock
	ttl    time.Duration
	mu     sync.Mutex
	items  map[string]secretCacheEntry
}

type secretCacheEntry struct {
	value     string
	expiresAt time.Time
}

func NewSecretCache(client SecretClient, ttl time.Duration, clock Clock) *SecretCache {
	if ttl <= 0 {
		panic("secret cache ttl must be positive")
	}
	if clock == nil {
		panic("clock is required")
	}
	return &SecretCache{client: client, ttl: ttl, clock: clock, items: map[string]secretCacheEntry{}}
}

func (c *SecretCache) Value(ctx context.Context, secretID string) (string, error) {
	now := c.clock.Now()
	c.mu.Lock()
	entry, ok := c.items[secretID]
	if ok && now.Before(entry.expiresAt) {
		c.mu.Unlock()
		return entry.value, nil
	}
	c.mu.Unlock()

	resp, err := c.client.ResolveSecret(ctx, &secretsv1.ResolveSecretRequest{Id: secretID})
	if err != nil {
		return "", err
	}
	value := resp.GetValue()
	c.mu.Lock()
	c.items[secretID] = secretCacheEntry{value: value, expiresAt: now.Add(c.ttl)}
	c.mu.Unlock()
	return value, nil
}
