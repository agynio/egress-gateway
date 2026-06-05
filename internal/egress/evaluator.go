package egress

import (
	"context"
	"fmt"
	"net/http"
	"path"
	"sort"
	"strings"

	egressv1 "github.com/agynio/egress-gateway/.gen/go/agynio/api/egress/v1"
)

type Evaluator struct {
	secrets *SecretCache
}

func NewEvaluator(secrets *SecretCache) *Evaluator {
	return &Evaluator{secrets: secrets}
}

func (e *Evaluator) Evaluate(ctx context.Context, req RequestContext, rules []*egressv1.EgressRule) (Evaluation, error) {
	matched, err := matchingRules(req, rules)
	if err != nil {
		return Evaluation{}, err
	}
	if hasDeny(matched) {
		return Evaluation{Outcome: OutcomeDeny, MatchedRules: matched, InjectedHeader: http.Header{}}, nil
	}
	headers, err := e.injectedHeaders(ctx, matched)
	if err != nil {
		return Evaluation{}, err
	}
	return Evaluation{Outcome: OutcomeAllow, MatchedRules: matched, InjectedHeader: headers}, nil
}

func matchingRules(req RequestContext, rules []*egressv1.EgressRule) ([]*egressv1.EgressRule, error) {
	matched := make([]*egressv1.EgressRule, 0, len(rules))
	for _, rule := range rules {
		matches, err := ruleMatches(req, rule)
		if err != nil {
			return nil, err
		}
		if matches {
			matched = append(matched, rule)
		}
	}
	sort.Slice(matched, func(i, j int) bool {
		return matched[i].GetMeta().GetId() < matched[j].GetMeta().GetId()
	})
	return matched, nil
}

func ruleMatches(req RequestContext, rule *egressv1.EgressRule) (bool, error) {
	matcher := rule.GetMatcher()
	pathMatched, err := pathMatches(req.Path, matcher.GetPathPattern())
	if err != nil {
		return false, fmt.Errorf("invalid path pattern for rule %s: %w", rule.GetMeta().GetId(), err)
	}
	return domainMatches(req.Host, matcher.GetDomainPattern()) &&
		portMatches(req.Port, matcher.GetPorts()) &&
		methodMatches(req.Method, matcher.GetMethods()) &&
		pathMatched, nil
}

func domainMatches(host string, pattern string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	pattern = strings.ToLower(strings.TrimSuffix(pattern, "."))
	if strings.HasPrefix(pattern, "*.") {
		suffix := strings.TrimPrefix(pattern, "*.")
		return strings.HasSuffix(host, "."+suffix) && host != suffix
	}
	return host == pattern
}

func portMatches(port int, ports []int32) bool {
	if len(ports) == 0 {
		return port == 80 || port == 443
	}
	for _, candidate := range ports {
		if int(candidate) == port {
			return true
		}
	}
	return false
}

func methodMatches(method string, methods []string) bool {
	if len(methods) == 0 {
		return true
	}
	for _, candidate := range methods {
		if strings.EqualFold(method, candidate) {
			return true
		}
	}
	return false
}

func pathMatches(requestPath string, pattern string) (bool, error) {
	if pattern == "" {
		return true, nil
	}
	matched, err := path.Match(pattern, requestPath)
	if err != nil {
		return false, err
	}
	return matched, nil
}

func hasDeny(rules []*egressv1.EgressRule) bool {
	for _, rule := range rules {
		if rule.GetEffect().GetAction() == egressv1.EgressRuleAction_EGRESS_RULE_ACTION_DENY {
			return true
		}
	}
	return false
}

func (e *Evaluator) injectedHeaders(ctx context.Context, rules []*egressv1.EgressRule) (http.Header, error) {
	merged := http.Header{}
	for _, rule := range rules {
		for _, header := range rule.GetEffect().GetInject() {
			value, err := e.headerValue(ctx, header)
			if err != nil {
				return nil, fmt.Errorf("resolve injected header for rule %s: %w", rule.GetMeta().GetId(), err)
			}
			merged.Set(header.GetName(), value)
		}
	}
	return merged, nil
}

func (e *Evaluator) headerValue(ctx context.Context, header *egressv1.EgressRuleHeader) (string, error) {
	credential, err := e.credential(ctx, header)
	if err != nil {
		return "", err
	}
	switch header.GetScheme() {
	case egressv1.HeaderAuthScheme_HEADER_AUTH_SCHEME_UNSPECIFIED:
		return credential, nil
	case egressv1.HeaderAuthScheme_HEADER_AUTH_SCHEME_BEARER:
		return "Bearer " + credential, nil
	case egressv1.HeaderAuthScheme_HEADER_AUTH_SCHEME_BASIC:
		return "Basic " + credential, nil
	default:
		panic("validated header auth scheme is invalid")
	}
}

func (e *Evaluator) credential(ctx context.Context, header *egressv1.EgressRuleHeader) (string, error) {
	switch value := header.GetCredential().(type) {
	case *egressv1.EgressRuleHeader_Value:
		return value.Value, nil
	case *egressv1.EgressRuleHeader_SecretId:
		return e.secrets.Value(ctx, value.SecretId)
	default:
		panic("validated injected header credential is missing")
	}
}
