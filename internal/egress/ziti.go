package egress

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/openziti/edge-api/rest_model"
	"github.com/openziti/sdk-golang/ziti"
	"github.com/openziti/sdk-golang/ziti/edge"
)

const egressServiceRole = "egress-services"

const defaultRoleReconcileInterval = 15 * time.Second

type ZitiContext interface {
	Authenticate() error
	RefreshServices() error
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
		return NewServiceRoleListener(ctx, egressServiceRole), nil
	}
	return listenForService(ctx, configuredServiceName)
}

type ServiceRoleListener struct {
	ctx       ZitiContext
	role      string
	interval  time.Duration
	acceptCh  chan DataPlaneConn
	closeCh   chan struct{}
	once      sync.Once
	mu        sync.Mutex
	listeners map[string]DataPlaneListener
}

func NewServiceRoleListener(ctx ZitiContext, role string) *ServiceRoleListener {
	return NewServiceRoleListenerWithInterval(ctx, role, defaultRoleReconcileInterval)
}

func NewServiceRoleListenerWithInterval(ctx ZitiContext, role string, interval time.Duration) *ServiceRoleListener {
	if ctx == nil {
		panic("ziti context is required")
	}
	if role == "" {
		panic("service role is required")
	}
	if interval <= 0 {
		panic("role reconcile interval must be positive")
	}
	listener := &ServiceRoleListener{ctx: ctx, role: role, interval: interval, acceptCh: make(chan DataPlaneConn), closeCh: make(chan struct{}), listeners: map[string]DataPlaneListener{}}
	go listener.run()
	return listener
}

func (l *ServiceRoleListener) Accept() (DataPlaneConn, error) {
	select {
	case conn := <-l.acceptCh:
		return conn, nil
	case <-l.closeCh:
		return nil, net.ErrClosed
	}
}

func (l *ServiceRoleListener) Close() error {
	l.once.Do(func() {
		close(l.closeCh)
		l.mu.Lock()
		listeners := l.listeners
		l.listeners = map[string]DataPlaneListener{}
		l.mu.Unlock()
		for _, listener := range listeners {
			_ = listener.Close()
		}
	})
	return nil
}

func (l *ServiceRoleListener) run() {
	l.reconcile()
	ticker := time.NewTicker(l.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			l.reconcile()
		case <-l.closeCh:
			return
		}
	}
}

func (l *ServiceRoleListener) reconcile() {
	if err := l.ctx.RefreshServices(); err != nil {
		log.Printf("refresh ziti services for role %s: %v", l.role, err)
		return
	}
	services, err := l.ctx.GetServices()
	if err != nil {
		log.Printf("list ziti services for role %s: %v", l.role, err)
		return
	}
	desired := l.desiredServices(services)
	l.closeRemovedServices(desired)
	for serviceName := range desired {
		l.ensureServiceListener(serviceName)
	}
}

func (l *ServiceRoleListener) desiredServices(services []rest_model.ServiceDetail) map[string]struct{} {
	desired := map[string]struct{}{}
	for _, service := range services {
		if service.Name == nil || !hasServiceRole(service.RoleAttributes, l.role) {
			continue
		}
		desired[*service.Name] = struct{}{}
	}
	return desired
}

func (l *ServiceRoleListener) closeRemovedServices(desired map[string]struct{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for serviceName, listener := range l.listeners {
		if _, ok := desired[serviceName]; ok {
			continue
		}
		delete(l.listeners, serviceName)
		_ = listener.Close()
	}
}

func (l *ServiceRoleListener) ensureServiceListener(serviceName string) {
	l.mu.Lock()
	_, exists := l.listeners[serviceName]
	l.mu.Unlock()
	if exists {
		return
	}
	listener, err := listenForService(l.ctx, serviceName)
	if err != nil {
		log.Printf("listen for ziti service %q with role %s: %v", serviceName, l.role, err)
		return
	}
	l.mu.Lock()
	if existing := l.listeners[serviceName]; existing != nil {
		l.mu.Unlock()
		_ = listener.Close()
		return
	}
	l.listeners[serviceName] = listener
	l.mu.Unlock()
	go l.acceptService(serviceName, listener)
}

func (l *ServiceRoleListener) acceptService(serviceName string, listener DataPlaneListener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			if !l.isClosed() {
				log.Printf("ziti service listener %q stopped: %v", serviceName, err)
			}
			_ = listener.Close()
			l.removeServiceListener(serviceName, listener)
			return
		}
		select {
		case l.acceptCh <- conn:
		case <-l.closeCh:
			_ = conn.Close()
			return
		}
	}
}

func (l *ServiceRoleListener) removeServiceListener(serviceName string, listener DataPlaneListener) {
	l.mu.Lock()
	if l.listeners[serviceName] == listener {
		delete(l.listeners, serviceName)
	}
	l.mu.Unlock()
}

func (l *ServiceRoleListener) isClosed() bool {
	select {
	case <-l.closeCh:
		return true
	default:
		return false
	}
}

func hasServiceRole(attributes *rest_model.Attributes, role string) bool {
	if attributes == nil {
		return false
	}
	for _, attribute := range *attributes {
		if strings.EqualFold(attribute, role) {
			return true
		}
	}
	return false
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
