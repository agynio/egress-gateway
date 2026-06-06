package egress

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/openziti/edge-api/rest_model"
	"github.com/openziti/sdk-golang/ziti"
	"github.com/openziti/sdk-golang/ziti/edge"
)

const egressServiceRole = "egress-services"

type ZitiContext interface {
	Authenticate() error
	GetServices() ([]rest_model.ServiceDetail, error)
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
		return listenForRoleServices(ctx)
	}
	return listenForService(ctx, configuredServiceName)
}

func listenForRoleServices(ctx ZitiContext) (DataPlaneListener, error) {
	serviceNames, err := resolveEgressServiceNames(ctx)
	if err != nil {
		return nil, err
	}
	listeners := make([]DataPlaneListener, 0, len(serviceNames))
	for _, serviceName := range serviceNames {
		listener, err := listenForService(ctx, serviceName)
		if err != nil {
			closeDataPlaneListeners(listeners)
			return nil, err
		}
		listeners = append(listeners, listener)
	}
	return NewMultiListener(listeners), nil
}

func listenForService(ctx ZitiContext, serviceName string) (DataPlaneListener, error) {
	listener, err := ctx.ListenWithOptions(serviceName, &ziti.ListenOptions{BindUsingEdgeIdentity: true})
	if err != nil {
		return nil, fmt.Errorf("listen for ziti service %q: %w", serviceName, err)
	}
	return NewListenerAdapter(listener), nil
}

func resolveEgressServiceNames(ctx ZitiContext) ([]string, error) {
	services, err := ctx.GetServices()
	if err != nil {
		return nil, fmt.Errorf("list ziti services: %w", err)
	}
	var serviceNames []string
	for _, service := range services {
		if service.Name == nil {
			continue
		}
		if hasEgressServiceRole(service.RoleAttributes) {
			serviceNames = append(serviceNames, *service.Name)
		}
	}
	if len(serviceNames) == 0 {
		return nil, errors.New("no ziti service with egress-services role is bindable")
	}
	return serviceNames, nil
}

func hasEgressServiceRole(attributes *rest_model.Attributes) bool {
	if attributes == nil {
		return false
	}
	for _, attribute := range *attributes {
		if strings.EqualFold(attribute, egressServiceRole) {
			return true
		}
	}
	return false
}

type ListenerAdapter struct {
	listener edge.Listener
	mu       sync.Mutex
	closed   bool
}

type MultiListener struct {
	listeners []DataPlaneListener
	acceptCh  chan acceptResult
	closeCh   chan struct{}
	once      sync.Once
}

type acceptResult struct {
	conn DataPlaneConn
	err  error
}

func NewMultiListener(listeners []DataPlaneListener) *MultiListener {
	if len(listeners) == 0 {
		panic("at least one data-plane listener is required")
	}
	m := &MultiListener{listeners: listeners, acceptCh: make(chan acceptResult), closeCh: make(chan struct{})}
	for _, listener := range listeners {
		go m.accept(listener)
	}
	return m
}

func (m *MultiListener) Accept() (DataPlaneConn, error) {
	select {
	case result := <-m.acceptCh:
		return result.conn, result.err
	case <-m.closeCh:
		return nil, net.ErrClosed
	}
}

func (m *MultiListener) Close() error {
	m.once.Do(func() {
		close(m.closeCh)
		closeDataPlaneListeners(m.listeners)
	})
	return nil
}

func (m *MultiListener) accept(listener DataPlaneListener) {
	for {
		conn, err := listener.Accept()
		select {
		case m.acceptCh <- acceptResult{conn: conn, err: err}:
		case <-m.closeCh:
			if conn != nil {
				conn.Close()
			}
			return
		}
		if err != nil {
			return
		}
	}
}

func closeDataPlaneListeners(listeners []DataPlaneListener) {
	for _, listener := range listeners {
		_ = listener.Close()
	}
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
