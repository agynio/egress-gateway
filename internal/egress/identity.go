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
}

func NewIdentityResolver(ziti ZitiIdentityClient, agents AgentIdentityClient) *IdentityResolver {
	return &IdentityResolver{ziti: ziti, agents: agents}
}

func (r *IdentityResolver) ResolveAgent(ctx context.Context, zitiIdentityID string) (AgentContext, error) {
	identity, err := r.ziti.ResolveIdentity(ctx, &zitimanagementv1.ResolveIdentityRequest{ZitiIdentityId: zitiIdentityID})
	if err != nil {
		return AgentContext{}, fmt.Errorf("resolve ziti identity: %w", err)
	}
	if identity.GetIdentityType() != identityv1.IdentityType_IDENTITY_TYPE_AGENT {
		return AgentContext{}, fmt.Errorf("resolved identity is not an agent")
	}
	agent, err := r.agents.ResolveAgentIdentity(ctx, &agentsv1.ResolveAgentIdentityRequest{IdentityId: identity.GetIdentityId()})
	if err != nil {
		return AgentContext{}, fmt.Errorf("resolve agent identity: %w", err)
	}
	return AgentContext{AgentID: agent.GetAgentId(), WorkloadID: identity.GetWorkloadId(), OrganizationID: agent.GetOrganizationId()}, nil
}
