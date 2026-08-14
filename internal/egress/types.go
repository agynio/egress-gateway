package egress

import (
	"net/http"
	"time"

	egressv1 "github.com/agynio/egress-gateway/.gen/go/agynio/api/egress/v1"
)

// AgentContext describes whatever runs behind an overlay identity. A sandbox
// has no agent, so AgentID is empty and only the environment identifies it.
type AgentContext struct {
	AgentID        string
	EnvironmentID  string
	WorkloadID     string
	OrganizationID string
}

// PrivateResourceContext identifies the mediated private resource a
// connection arrived for, resolved from the OpenZiti service name.
type PrivateResourceContext struct {
	ID            string
	InterceptHost string
	// "http" or "https" -- the resource's protocol, which decides whether the
	// inbound connection carries TLS to terminate.
	Scheme string
}

type RequestContext struct {
	Agent           AgentContext
	Method          string
	Scheme          string
	Host            string
	Port            int
	Path            string
	RequestID       string
	ReceivedTime    time.Time
	PrivateResource *PrivateResourceContext
}

type Outcome string

const (
	OutcomeAllow         Outcome = "allow"
	OutcomeDeny          Outcome = "deny"
	OutcomeBypass        Outcome = "bypass"
	OutcomeUpstreamError Outcome = "upstream_error"
	OutcomeTLSError      Outcome = "tls_error"
	// A mediated connection whose caller holds no rule naming the resource:
	// passed through byte-for-byte, nothing decrypted or parsed.
	OutcomeSpliced Outcome = "spliced"
	// A mediated connection refused because the caller's rule set could not
	// be determined -- guessing splice would silently bypass a deny or drop a
	// credential.
	OutcomeRulesUnavailable Outcome = "rules_unavailable"
)

type AppliedRule struct {
	Rule *egressv1.EgressRule
}

type Evaluation struct {
	Outcome        Outcome
	MatchedRules   []*egressv1.EgressRule
	InjectedHeader http.Header
	// TLS settings for the gateway->target leg of a private https
	// destination, from the matched rule carrying one.
	UpstreamTLS *egressv1.EgressRuleUpstreamTls
}

type RequestMetrics struct {
	Context        RequestContext
	Outcome        Outcome
	MatchedRuleIDs []string
	UpstreamStatus int
	BytesIn        int64
	BytesOut       int64
	Latency        time.Duration
	StartedAt      time.Time
	CompletedAt    time.Time
}
