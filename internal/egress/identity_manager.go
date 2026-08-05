package egress

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	zitimanagementv1 "github.com/agynio/egress-gateway/.gen/go/agynio/api/ziti_management/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	serviceIdentityFileMode      = 0o600
	defaultIdentityLeaseInterval = 30 * time.Second
)

// ErrIdentityLost reports that the egress gateway's OpenZiti identity no longer
// exists (garbage-collected while the pod was running). Recovery is a pod
// restart: a fresh pod enrolls a fresh identity.
var ErrIdentityLost = errors.New("ziti identity lost")

type ServiceIdentityManager struct {
	client        zitimanagementv1.ZitiManagementServiceClient
	identityFile  string
	leaseInterval time.Duration
}

func NewServiceIdentityManager(client zitimanagementv1.ZitiManagementServiceClient, identityFile string, leaseInterval time.Duration) *ServiceIdentityManager {
	if client == nil {
		panic("ziti management client is required")
	}
	if identityFile == "" {
		panic("ziti identity file is required")
	}
	if leaseInterval <= 0 {
		leaseInterval = defaultIdentityLeaseInterval
	}
	return &ServiceIdentityManager{client: client, identityFile: identityFile, leaseInterval: leaseInterval}
}

func (m *ServiceIdentityManager) Enroll(ctx context.Context) (string, error) {
	resp, err := m.client.RequestServiceIdentity(ctx, &zitimanagementv1.RequestServiceIdentityRequest{ServiceType: zitimanagementv1.ServiceType_SERVICE_TYPE_EGRESS_GATEWAY})
	if err != nil {
		return "", fmt.Errorf("request egress gateway service identity: %w", err)
	}
	if resp.GetZitiIdentityId() == "" {
		return "", fmt.Errorf("request egress gateway service identity returned empty identity id")
	}
	if len(resp.GetIdentityJson()) == 0 {
		return "", fmt.Errorf("request egress gateway service identity returned empty identity json")
	}
	if err := os.MkdirAll(filepath.Dir(m.identityFile), 0o700); err != nil {
		return "", fmt.Errorf("create ziti identity directory: %w", err)
	}
	if err := os.WriteFile(m.identityFile, resp.GetIdentityJson(), serviceIdentityFileMode); err != nil {
		return "", fmt.Errorf("write ziti identity file: %w", err)
	}
	return resp.GetZitiIdentityId(), nil
}

// RunLeaseExtender extends the identity lease until ctx is cancelled (returns
// nil) or the identity is definitively gone (returns an error wrapping
// ErrIdentityLost). Identity loss is fatal by design: the caller must log the
// error and terminate so the pod restart path enrolls a fresh identity.
// Transient extension failures are logged and retried on the next tick.
func (m *ServiceIdentityManager) RunLeaseExtender(ctx context.Context, zitiIdentityID string) error {
	if zitiIdentityID == "" {
		panic("ziti identity id is required")
	}
	ticker := time.NewTicker(m.leaseInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			err := m.extendLease(ctx, zitiIdentityID)
			if err == nil {
				continue
			}
			if ctx.Err() != nil {
				return nil
			}
			if status.Code(err) == codes.NotFound {
				return fmt.Errorf("%w: identity %s no longer exists: %v", ErrIdentityLost, zitiIdentityID, err)
			}
			log.Printf("extend egress gateway ziti identity lease for %s: %v", zitiIdentityID, err)
		case <-ctx.Done():
			return nil
		}
	}
}

func (m *ServiceIdentityManager) extendLease(ctx context.Context, zitiIdentityID string) error {
	_, err := m.client.ExtendIdentityLease(ctx, &zitimanagementv1.ExtendIdentityLeaseRequest{ZitiIdentityId: zitiIdentityID})
	return err
}
