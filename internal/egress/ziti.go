package egress

import (
	"fmt"
	"net"
	"sync"

	"github.com/openziti/sdk-golang/ziti"
	"github.com/openziti/sdk-golang/ziti/edge"
)

const egressServiceRole = "egress-services"

const roleServiceName = "#" + egressServiceRole

type ZitiContext interface {
	Authenticate() error
	ListenWithOptions(serviceName string, options *ziti.ListenOptions) (edge.Listener, error)
	Close()
}

func LoadZitiContext(identityFile string) (ZitiContext, error) {
	ctx, err := ziti.NewContextFromFile(identityFile)
	if err != nil {
		return nil, fmt.Errorf("load ziti identity: %w", err)
	}
	if err := ctx.Authenticate(); err != nil {
		ctx.Close()
		return nil, fmt.Errorf("authenticate ziti identity: %w", err)
	}
	return ctx, nil
}

func ListenForEgressServices(ctx ZitiContext, configuredServiceName string) (DataPlaneListener, error) {
	if configuredServiceName == "" {
		return listenForService(ctx, roleServiceName)
	}
	return listenForService(ctx, configuredServiceName)
}

func listenForService(ctx ZitiContext, serviceName string) (DataPlaneListener, error) {
	listener, err := ctx.ListenWithOptions(serviceName, &ziti.ListenOptions{BindUsingEdgeIdentity: true})
	if err != nil {
		return nil, fmt.Errorf("listen for ziti service %q: %w", serviceName, err)
	}
	return NewListenerAdapter(listener), nil
}

type ListenerAdapter struct {
	listener edge.Listener
	mu       sync.Mutex
	closed   bool
}

func NewListenerAdapter(listener edge.Listener) *ListenerAdapter {
	if listener == nil {
		panic("ziti listener is required")
	}
	return &ListenerAdapter{listener: listener}
}

func (l *ListenerAdapter) Accept() (DataPlaneConn, error) {
	conn, err := l.listener.AcceptEdge()
	if err != nil {
		if l.isClosed() {
			return nil, net.ErrClosed
		}
		return nil, err
	}
	if err := conn.CompleteAcceptSuccess(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("complete ziti accept: %w", err)
	}
	return &ConnAdapter{Conn: conn}, nil
}

func (l *ListenerAdapter) Close() error {
	l.mu.Lock()
	l.closed = true
	l.mu.Unlock()
	return l.listener.Close()
}

func (l *ListenerAdapter) isClosed() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.closed || l.listener.IsClosed()
}

type ConnAdapter struct {
	edge.Conn
}

func (c *ConnAdapter) DialerIdentityID() string {
	return c.GetDialerIdentityId()
}

func (c *ConnAdapter) AppData() []byte {
	return c.GetAppData()
}
