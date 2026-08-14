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

// RuleSet is a caller's effective rules plus the denormalized fields of every
// private resource those rules name, keyed by private_resource_id.
type RuleSet struct {
	Rules            []*egressv1.EgressRule
	PrivateResources map[string]*egressv1.PrivateResourceInfo
}

type ruleCacheEntry struct {
	ruleSet   RuleSet
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
	ruleSet, err := c.RuleSetFor(ctx, agentID, environmentID)
	if err != nil {
		return nil, err
	}
	return ruleSet.Rules, nil
}

func (c *RuleCache) RuleSetFor(ctx context.Context, agentID string, environmentID string) (RuleSet, error) {
	key := agentID + "|" + environmentID
	now := c.clock.Now()
	c.mu.Lock()
	entry, ok := c.items[key]
	if ok && now.Before(entry.expiresAt) {
		ruleSet := cloneRuleSet(entry.ruleSet)
		c.mu.Unlock()
		return ruleSet, nil
	}
	c.mu.Unlock()

	ruleSet := RuleSet{Rules: []*egressv1.EgressRule{}, PrivateResources: map[string]*egressv1.PrivateResourceInfo{}}
	if agentID != "" {
		resp, err := c.client.ListEgressRulesByAgent(ctx, &egressv1.ListEgressRulesByAgentRequest{AgentId: agentID})
		if err != nil {
			return c.staleOrError(key, entry, ok, now, err)
		}
		ruleSet.Rules = append(ruleSet.Rules, resp.GetEgressRules()...)
		mergeResourceInfos(ruleSet.PrivateResources, resp.GetPrivateResources())
	}
	if environmentID != "" {
		resp, err := c.client.ListEgressRulesByEnvironment(ctx, &egressv1.ListEgressRulesByEnvironmentRequest{EnvironmentId: environmentID})
		if err != nil {
			return c.staleOrError(key, entry, ok, now, err)
		}
		ruleSet.Rules = append(ruleSet.Rules, resp.GetEgressRules()...)
		mergeResourceInfos(ruleSet.PrivateResources, resp.GetPrivateResources())
	}
	ruleSet.Rules = dedupeRules(ruleSet.Rules)
	c.mu.Lock()
	c.items[key] = ruleCacheEntry{ruleSet: cloneRuleSet(ruleSet), expiresAt: c.clock.Now().Add(c.ttl)}
	c.mu.Unlock()
	return cloneRuleSet(ruleSet), nil
}

func mergeResourceInfos(into map[string]*egressv1.PrivateResourceInfo, from map[string]*egressv1.PrivateResourceInfo) {
	for id, info := range from {
		into[id] = info
	}
}

func (c *RuleCache) staleOrError(key string, entry ruleCacheEntry, ok bool, now time.Time, err error) (RuleSet, error) {
	if ok && !now.After(entry.expiresAt.Add(c.staleIfError)) {
		if c.failureHandler != nil {
			c.failureHandler(key, err)
		}
		return cloneRuleSet(entry.ruleSet), nil
	}
	return RuleSet{}, err
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

// InvalidatePrivateResource drops every entry whose rules name the resource:
// the entries carry the resource's intercept_host and protocol denormalized,
// and UpdatePrivateResource changes those without touching any rule.
func (c *RuleCache) InvalidatePrivateResource(resourceID string) {
	if resourceID == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, entry := range c.items {
		if _, ok := entry.ruleSet.PrivateResources[resourceID]; ok {
			delete(c.items, key)
		}
	}
}

func cloneRules(rules []*egressv1.EgressRule) []*egressv1.EgressRule {
	cloned := make([]*egressv1.EgressRule, len(rules))
	copy(cloned, rules)
	return cloned
}

func cloneRuleSet(ruleSet RuleSet) RuleSet {
	cloned := RuleSet{Rules: cloneRules(ruleSet.Rules), PrivateResources: map[string]*egressv1.PrivateResourceInfo{}}
	mergeResourceInfos(cloned.PrivateResources, ruleSet.PrivateResources)
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
