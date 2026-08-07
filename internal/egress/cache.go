package egress

import (
	"context"
	"strings"
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
	ListEgressRulesByEnvironment(context.Context, *egressv1.ListEgressRulesByEnvironmentRequest, ...grpc.CallOption) (*egressv1.ListEgressRulesByEnvironmentResponse, error)
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

// Rules is the union of what is attached to the agent and to the environment
// it runs. A sandbox has no agent, so the environment is all it has.
func (c *RuleCache) Rules(ctx context.Context, agentID string) ([]*egressv1.EgressRule, error) {
	return c.RulesFor(ctx, agentID, "")
}

func (c *RuleCache) RulesFor(ctx context.Context, agentID string, environmentID string) ([]*egressv1.EgressRule, error) {
	key := agentID + "|" + environmentID
	now := c.clock.Now()
	c.mu.Lock()
	entry, ok := c.items[key]
	if ok && now.Before(entry.expiresAt) {
		rules := cloneRules(entry.rules)
		c.mu.Unlock()
		return rules, nil
	}
	c.mu.Unlock()

	rules := []*egressv1.EgressRule{}
	if agentID != "" {
		resp, err := c.client.ListEgressRulesByAgent(ctx, &egressv1.ListEgressRulesByAgentRequest{AgentId: agentID})
		if err != nil {
			return c.staleOrError(key, entry, ok, now, err)
		}
		rules = append(rules, resp.GetEgressRules()...)
	}
	if environmentID != "" {
		resp, err := c.client.ListEgressRulesByEnvironment(ctx, &egressv1.ListEgressRulesByEnvironmentRequest{EnvironmentId: environmentID})
		if err != nil {
			return c.staleOrError(key, entry, ok, now, err)
		}
		rules = append(rules, resp.GetEgressRules()...)
	}
	rules = dedupeRules(rules)
	c.mu.Lock()
	c.items[key] = ruleCacheEntry{rules: cloneRules(rules), expiresAt: c.clock.Now().Add(c.ttl)}
	c.mu.Unlock()
	return cloneRules(rules), nil
}

func (c *RuleCache) staleOrError(key string, entry ruleCacheEntry, ok bool, now time.Time, err error) ([]*egressv1.EgressRule, error) {
	if ok && !now.After(entry.expiresAt.Add(c.staleIfError)) {
		if c.failureHandler != nil {
			c.failureHandler(key, err)
		}
		return cloneRules(entry.rules), nil
	}
	return nil, err
}

// A rule attached to both an agent and the environment it runs resolves once.
func dedupeRules(rules []*egressv1.EgressRule) []*egressv1.EgressRule {
	seen := map[string]struct{}{}
	deduped := make([]*egressv1.EgressRule, 0, len(rules))
	for _, rule := range rules {
		id := rule.GetMeta().GetId()
		if _, done := seen[id]; done {
			continue
		}
		seen[id] = struct{}{}
		deduped = append(deduped, rule)
	}
	return deduped
}

// Invalidate drops every entry the id takes part in: the key pairs an agent
// with the environment it runs, and a change to either invalidates the union.
func (c *RuleCache) Invalidate(id string) {
	if id == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for key := range c.items {
		agentID, environmentID, _ := strings.Cut(key, "|")
		if agentID == id || environmentID == id {
			delete(c.items, key)
		}
	}
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
