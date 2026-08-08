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

type RequestContext struct {
	Agent        AgentContext
	Method       string
	Scheme       string
	Host         string
	Port         int
	Path         string
	RequestID    string
	ReceivedTime time.Time
}

type Outcome string

const (
	OutcomeAllow         Outcome = "allow"
	OutcomeDeny          Outcome = "deny"
	OutcomeBypass        Outcome = "bypass"
	OutcomeUpstreamError Outcome = "upstream_error"
	OutcomeTLSError      Outcome = "tls_error"
)

type AppliedRule struct {
	Rule *egressv1.EgressRule
}

type Evaluation struct {
	Outcome        Outcome
	MatchedRules   []*egressv1.EgressRule
	InjectedHeader http.Header
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
