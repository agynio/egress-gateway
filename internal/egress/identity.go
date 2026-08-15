package egress

import (
	"context"
	"fmt"

	agentsv1 "github.com/agynio/egress-gateway/.gen/go/agynio/api/agents/v1"
	identityv1 "github.com/agynio/egress-gateway/.gen/go/agynio/api/identity/v1"
	zitimanagementv1 "github.com/agynio/egress-gateway/.gen/go/agynio/api/ziti_management/v1"
	"google.golang.org/grpc"
)

type IdentityResolver struct {
	ziti   ZitiIdentityClient
	agents AgentIdentityClient
}

type ZitiIdentityClient interface {
	ResolveIdentity(context.Context, *zitimanagementv1.ResolveIdentityRequest, ...grpc.CallOption) (*zitimanagementv1.ResolveIdentityResponse, error)
}

type AgentIdentityClient interface {
	ResolveAgentIdentity(context.Context, *agentsv1.ResolveAgentIdentityRequest, ...grpc.CallOption) (*agentsv1.ResolveAgentIdentityResponse, error)
	GetAgent(context.Context, *agentsv1.GetAgentRequest, ...grpc.CallOption) (*agentsv1.GetAgentResponse, error)
	GetSandbox(context.Context, *agentsv1.GetSandboxRequest, ...grpc.CallOption) (*agentsv1.GetSandboxResponse, error)
}

func NewIdentityResolver(ziti ZitiIdentityClient, agents AgentIdentityClient) *IdentityResolver {
	return &IdentityResolver{ziti: ziti, agents: agents}
}

// DialerContext is who dialed a mediated private resource. Only workloads
// can hold egress rules; every other identity type -- a user's device, an
// app -- reached the resource through an access grant and is spliced.
type DialerContext struct {
	Agent      AgentContext
	IsWorkload bool
}

func (r *IdentityResolver) ResolveDialer(ctx context.Context, zitiIdentityID string) (DialerContext, error) {
	identity, err := r.ziti.ResolveIdentity(ctx, &zitimanagementv1.ResolveIdentityRequest{ZitiIdentityId: zitiIdentityID})
	if err != nil {
		return DialerContext{}, fmt.Errorf("resolve ziti identity: %w", err)
	}
	switch identity.GetIdentityType() {
	case identityv1.IdentityType_IDENTITY_TYPE_SANDBOX, identityv1.IdentityType_IDENTITY_TYPE_AGENT:
		agent, err := r.resolveWorkload(ctx, identity)
		if err != nil {
			return DialerContext{}, err
		}
		return DialerContext{Agent: agent, IsWorkload: true}, nil
	default:
		return DialerContext{}, nil
	}
}

func (r *IdentityResolver) ResolveAgent(ctx context.Context, zitiIdentityID string) (AgentContext, error) {
	identity, err := r.ziti.ResolveIdentity(ctx, &zitimanagementv1.ResolveIdentityRequest{ZitiIdentityId: zitiIdentityID})
	if err != nil {
		return AgentContext{}, fmt.Errorf("resolve ziti identity: %w", err)
	}
	return r.resolveWorkload(ctx, identity)
}

func (r *IdentityResolver) resolveWorkload(ctx context.Context, identity *zitimanagementv1.ResolveIdentityResponse) (AgentContext, error) {
	switch identity.GetIdentityType() {
	case identityv1.IdentityType_IDENTITY_TYPE_SANDBOX:
		// A sandbox carries no agent. Its rules come from the environment it
		// runs, which is the only thing an egress rule can be attached to for it.
		sandbox, err := r.agents.GetSandbox(ctx, &agentsv1.GetSandboxRequest{
			Ref: &agentsv1.GetSandboxRequest_Id{Id: identity.GetIdentityId()},
		})
		if err != nil {
			return AgentContext{}, fmt.Errorf("resolve sandbox identity: %w", err)
		}
		return AgentContext{
			EnvironmentID:  sandbox.GetSandbox().GetEnvironmentId(),
			WorkloadID:     identity.GetWorkloadId(),
			OrganizationID: sandbox.GetSandbox().GetOrganizationId(),
		}, nil
	case identityv1.IdentityType_IDENTITY_TYPE_AGENT:
	default:
		return AgentContext{}, fmt.Errorf("resolved identity is neither an agent nor a sandbox")
	}
	agent, err := r.agents.ResolveAgentIdentity(ctx, &agentsv1.ResolveAgentIdentityRequest{IdentityId: identity.GetIdentityId()})
	if err != nil {
		return AgentContext{}, fmt.Errorf("resolve agent identity: %w", err)
	}
	// An agent's rules are the union of its own and its environment's.
	environmentID := ""
	if detail, err := r.agents.GetAgent(ctx, &agentsv1.GetAgentRequest{Id: agent.GetAgentId()}); err == nil {
		environmentID = detail.GetAgent().GetEnvironmentId()
	}
	return AgentContext{
		AgentID:        agent.GetAgentId(),
		EnvironmentID:  environmentID,
		WorkloadID:     identity.GetWorkloadId(),
		OrganizationID: agent.GetOrganizationId(),
	}, nil
}
