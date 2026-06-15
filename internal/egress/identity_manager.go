package egress

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	zitimanagementv1 "github.com/agynio/egress-gateway/.gen/go/agynio/api/ziti_management/v1"
)

const (
	serviceIdentityFileMode      = 0o600
	defaultIdentityLeaseInterval = 30 * time.Second
)

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

func (m *ServiceIdentityManager) RunLeaseExtender(ctx context.Context, zitiIdentityID string) {
	if zitiIdentityID == "" {
		panic("ziti identity id is required")
	}
	ticker := time.NewTicker(m.leaseInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := m.extendLease(ctx, zitiIdentityID); err != nil {
				log.Printf("extend egress gateway ziti identity lease: %v", err)
			}
		case <-ctx.Done():
			return
		}
	}
}

func (m *ServiceIdentityManager) extendLease(ctx context.Context, zitiIdentityID string) error {
	_, err := m.client.ExtendIdentityLease(ctx, &zitimanagementv1.ExtendIdentityLeaseRequest{ZitiIdentityId: zitiIdentityID})
	return err
}
