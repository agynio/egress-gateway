package egress

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"unicode/utf8"

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
	if len(matched) == 0 {
		return Evaluation{Outcome: OutcomeBypass, MatchedRules: matched, InjectedHeader: http.Header{}}, nil
	}
	headers, err := e.injectedHeaders(ctx, matched)
	if err != nil {
		return Evaluation{}, err
	}
	return Evaluation{Outcome: OutcomeAllow, MatchedRules: matched, InjectedHeader: headers, UpstreamTLS: upstreamTLSFromRules(matched)}, nil
}

// The gateway->target TLS settings come from the matched rules; when several
// carry one, the lexicographically later rule id wins, mirroring the header
// merge.
func upstreamTLSFromRules(matched []*egressv1.EgressRule) *egressv1.EgressRuleUpstreamTls {
	var selected *egressv1.EgressRuleUpstreamTls
	for _, rule := range matched {
		if rule.GetUpstreamTls() != nil {
			selected = rule.GetUpstreamTls()
		}
	}
	return selected
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
	if !pathMatched || !methodMatches(req.Method, matcher.GetMethods()) {
		return false, nil
	}
	// The destination test: the resource the connection arrived on for a
	// private request, the SNI/Host and port for a public one. A private rule
	// never matches public traffic and vice versa.
	if req.PrivateResource != nil {
		return matcher.GetPrivateResourceId() != "" && matcher.GetPrivateResourceId() == req.PrivateResource.ID, nil
	}
	if matcher.GetPrivateResourceId() != "" {
		return false, nil
	}
	return domainMatches(req.Host, matcher.GetDomainPattern()) &&
		portMatches(req.Port, matcher.GetPorts()), nil
}

func domainMatches(host string, pattern string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	pattern = strings.ToLower(strings.TrimSuffix(pattern, "."))
	if strings.HasPrefix(pattern, "*.") {
		suffix := strings.TrimPrefix(pattern, "*.")
		if !strings.HasSuffix(host, "."+suffix) || host == suffix {
			return false
		}
		prefix := strings.TrimSuffix(host, "."+suffix)
		return !strings.Contains(prefix, ".") && prefix != ""
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
	matched, err := globPathMatch(pattern, requestPath)
	if err != nil {
		return false, err
	}
	return matched, nil
}

func globPathMatch(pattern string, requestPath string) (bool, error) {
	if _, err := compilePathGlob(pattern); err != nil {
		return false, err
	}
	return matchPathGlob(pattern, requestPath), nil
}

func compilePathGlob(pattern string) ([]rune, error) {
	if !utf8.ValidString(pattern) {
		return nil, fmt.Errorf("path pattern must be valid UTF-8")
	}
	runes := []rune(pattern)
	for i := 0; i < len(runes); i++ {
		switch runes[i] {
		case '[':
			return nil, fmt.Errorf("character classes are not supported")
		case '\\':
			return nil, fmt.Errorf("escapes are not supported")
		}
	}
	return runes, nil
}

func matchPathGlob(pattern string, requestPath string) bool {
	patternRunes := []rune(pattern)
	pathRunes := []rune(requestPath)
	matches := make([][]bool, len(patternRunes)+1)
	for i := range matches {
		matches[i] = make([]bool, len(pathRunes)+1)
	}
	matches[0][0] = true
	for patternIndex := 0; patternIndex < len(patternRunes); patternIndex++ {
		for pathIndex := 0; pathIndex <= len(pathRunes); pathIndex++ {
			if !matches[patternIndex][pathIndex] {
				continue
			}
			if isRecursiveGlob(patternRunes, patternIndex) {
				matches[patternIndex+2][pathIndex] = true
				if pathIndex < len(pathRunes) {
					matches[patternIndex][pathIndex+1] = true
				}
				continue
			}
			if pathIndex >= len(pathRunes) {
				continue
			}
			switch patternRunes[patternIndex] {
			case '*':
				if pathRunes[pathIndex] != '/' {
					matches[patternIndex][pathIndex+1] = true
				}
				matches[patternIndex+1][pathIndex] = true
			case '?':
				if pathRunes[pathIndex] != '/' {
					matches[patternIndex+1][pathIndex+1] = true
				}
			default:
				if patternRunes[patternIndex] == pathRunes[pathIndex] {
					matches[patternIndex+1][pathIndex+1] = true
				}
			}
		}
	}
	return matches[len(patternRunes)][len(pathRunes)]
}

func isRecursiveGlob(pattern []rune, index int) bool {
	return index+1 < len(pattern) && pattern[index] == '*' && pattern[index+1] == '*'
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
		// RFC 7617: the wire value is base64 of user:password, not the password alone.
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(header.GetUsername()+":"+credential)), nil
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
