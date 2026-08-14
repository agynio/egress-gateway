package egress

import (
	"context"
	"log"
	"net/http"
	"sort"
	"time"

	egressv1 "github.com/agynio/egress-gateway/.gen/go/agynio/api/egress/v1"
)

type Runtime struct {
	rules     *RuleCache
	evaluator *Evaluator
	forwarder *Forwarder
	observed  *Observability
}

func NewRuntime(rules *RuleCache, evaluator *Evaluator, forwarder *Forwarder, observed *Observability) *Runtime {
	if rules == nil {
		panic("rule cache is required")
	}
	if evaluator == nil {
		panic("evaluator is required")
	}
	if forwarder == nil {
		panic("forwarder is required")
	}
	return &Runtime{rules: rules, evaluator: evaluator, forwarder: forwarder, observed: observed}
}

func (r *Runtime) ServeRequest(ctx context.Context, w http.ResponseWriter, req *http.Request, requestContext RequestContext) error {
	rules, err := r.rules.RulesFor(ctx, requestContext.Agent.AgentID, requestContext.Agent.EnvironmentID)
	if err != nil {
		if requestContext.PrivateResource != nil {
			// "No rule applies" and "cannot tell" differ by whether a deny is
			// enforced and a credential injected; refuse rather than guess.
			http.Error(w, "egress gateway could not determine the rule set", http.StatusBadGateway)
			if r.observed != nil {
				r.emitObservability(ctx, RequestMetrics{Context: requestContext, Outcome: OutcomeRulesUnavailable, UpstreamStatus: http.StatusBadGateway})
			}
			return err
		}
		http.Error(w, "egress gateway could not load rules", http.StatusBadGateway)
		if r.observed != nil {
			r.emitObservability(ctx, RequestMetrics{Context: requestContext, Outcome: OutcomeUpstreamError, UpstreamStatus: http.StatusBadGateway})
		}
		return err
	}
	evaluation, err := r.evaluator.Evaluate(ctx, requestContext, rules)
	if err != nil {
		http.Error(w, "egress gateway could not apply rule effects", http.StatusBadGateway)
		if r.observed != nil {
			r.emitObservability(ctx, RequestMetrics{Context: requestContext, Outcome: OutcomeUpstreamError, MatchedRuleIDs: matchedRuleIDs(evaluation.MatchedRules), UpstreamStatus: http.StatusBadGateway})
		}
		return err
	}
	if evaluation.Outcome == OutcomeBypass {
		// A private connection is inspected per destination, not per request:
		// a request the rule's narrowing excludes is forwarded unchanged.
		if requestContext.PrivateResource != nil {
			evaluation = Evaluation{Outcome: OutcomeAllow, InjectedHeader: http.Header{}, UpstreamTLS: upstreamTLSFromRules(privateRulesForResource(rules, requestContext.PrivateResource.ID))}
		} else {
			// Otherwise indistinguishable from an upstream 404 by the caller.
			log.Printf("egress bypass: agent=%q environment=%q rules=%d %s %s://%s:%d%s",
				requestContext.Agent.AgentID, requestContext.Agent.EnvironmentID, len(rules),
				requestContext.Method, requestContext.Scheme, requestContext.Host, requestContext.Port, requestContext.Path)
			http.Error(w, "egress gateway bypassed unmatched destination", http.StatusNotFound)
			return nil
		}
	}
	metrics := r.forwarder.ServeHTTP(w, req, requestContext, evaluation)
	if r.observed != nil {
		r.emitObservability(ctx, metrics)
	}
	return nil
}

// privateRulesForResource keeps the upstream TLS settings applicable even for
// a request the rules' narrowing excluded from injection.
func privateRulesForResource(rules []*egressv1.EgressRule, resourceID string) []*egressv1.EgressRule {
	matched := []*egressv1.EgressRule{}
	for _, rule := range rules {
		if rule.GetMatcher().GetPrivateResourceId() == resourceID {
			matched = append(matched, rule)
		}
	}
	sort.Slice(matched, func(i, j int) bool { return matched[i].GetMeta().GetId() < matched[j].GetMeta().GetId() })
	return matched
}

// RuleSetFor exposes the cached rule set for the pre-TLS splice decision on a
// mediated connection.
func (r *Runtime) RuleSetFor(ctx context.Context, agent AgentContext) (RuleSet, error) {
	return r.rules.RuleSetFor(ctx, agent.AgentID, agent.EnvironmentID)
}

// EmitConnOutcome records a connection-level decision that never reached the
// request layer: a splice failure or a refusal.
func (r *Runtime) EmitConnOutcome(ctx context.Context, requestContext RequestContext, outcome Outcome) {
	if r.observed != nil {
		r.emitObservability(ctx, RequestMetrics{Context: requestContext, Outcome: outcome, StartedAt: requestContext.ReceivedTime, CompletedAt: time.Now()})
	}
}

func (r *Runtime) EmitMetrics(ctx context.Context, metrics RequestMetrics) {
	if r.observed != nil {
		r.emitObservability(ctx, metrics)
	}
}

func (r *Runtime) EmitTLSFailure(ctx context.Context, requestContext RequestContext) {
	if r.observed != nil {
		r.emitObservability(ctx, RequestMetrics{Context: requestContext, Outcome: OutcomeTLSError})
	}
}

func (r *Runtime) emitObservability(ctx context.Context, metrics RequestMetrics) {
	if err := r.observed.Emit(ctx, metrics); err != nil {
		log.Printf("emit egress observability: %v", err)
	}
}
