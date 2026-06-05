package egress

import (
	"context"
	"net/http"
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
	rules, err := r.rules.Rules(ctx, requestContext.Agent.AgentID)
	if err != nil {
		http.Error(w, "egress gateway could not load rules", http.StatusBadGateway)
		if r.observed != nil {
			r.observed.Emit(ctx, RequestMetrics{Context: requestContext, Outcome: OutcomeUpstreamError, UpstreamStatus: http.StatusBadGateway})
		}
		return err
	}
	evaluation, err := r.evaluator.Evaluate(ctx, requestContext, rules)
	if err != nil {
		http.Error(w, "egress gateway could not apply rule effects", http.StatusBadGateway)
		if r.observed != nil {
			r.observed.Emit(ctx, RequestMetrics{Context: requestContext, Outcome: OutcomeUpstreamError, MatchedRuleIDs: matchedRuleIDs(evaluation.MatchedRules), UpstreamStatus: http.StatusBadGateway})
		}
		return err
	}
	metrics := r.forwarder.ServeHTTP(w, req, requestContext, evaluation)
	if r.observed != nil {
		r.observed.Emit(ctx, metrics)
	}
	return nil
}
