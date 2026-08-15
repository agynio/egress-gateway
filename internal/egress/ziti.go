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
	Dial(serviceName string) (edge.Conn, error)
	Close()
}

// ZitiDialer opens the upstream leg of a mediated private resource: the
// tunnel-bound private-<id>-upstream-<port> service.
type ZitiDialer interface {
	DialService(serviceName string) (net.Conn, error)
}

type contextDialer struct {
	ctx ZitiContext
}

func NewZitiDialer(ctx ZitiContext) ZitiDialer {
	return &contextDialer{ctx: ctx}
}

func (d *contextDialer) DialService(serviceName string) (net.Conn, error) {
	conn, err := d.ctx.Dial(serviceName)
	if err != nil {
		return nil, fmt.Errorf("dial ziti service %q: %w", serviceName, err)
	}
	return conn, nil
}

func LoadZitiContext(identityFile string) (ZitiContext, error) {
	cfg, err := ziti.NewConfigFromFile(identityFile)
	if err != nil {
		return nil, fmt.Errorf("load ziti identity: %w", err)
	}
	// The controller returns a service's config blocks only for requested
	// config types; the interception is where a mediated resource's port set
	// comes from.
	cfg.ConfigTypes = append(cfg.ConfigTypes, "intercept.v1")
	ctx, err := ziti.NewContext(cfg)
	if err != nil {
		return nil, fmt.Errorf("create ziti context: %w", err)
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
	for serviceName, interceptPorts := range desired {
		l.ensureServiceListener(serviceName, interceptPorts)
	}
}

func (l *ServiceRoleListener) desiredServices(services []rest_model.ServiceDetail) map[string][]int {
	desired := map[string][]int{}
	for _, service := range services {
		if service.Name == nil || !hasServiceRole(service.RoleAttributes, l.role) {
			continue
		}
		desired[*service.Name] = interceptPortsFromConfig(service.Config)
	}
	return desired
}

// interceptPortsFromConfig reads the intercept.v1 port ranges off the bound
// service. The dialing sidecar's app data reports the diverter's local port
// rather than the port the caller dialed, so the service's own interception
// is the authoritative port set.
func interceptPortsFromConfig(config map[string]map[string]interface{}) []int {
	intercept, ok := config["intercept.v1"]
	if !ok {
		return nil
	}
	ranges, ok := intercept["portRanges"].([]interface{})
	if !ok {
		return nil
	}
	ports := []int{}
	for _, entry := range ranges {
		portRange, ok := entry.(map[string]interface{})
		if !ok {
			continue
		}
		low, lowOK := numericPort(portRange["low"])
		high, highOK := numericPort(portRange["high"])
		if !lowOK || !highOK || high < low || high-low > 65535 {
			continue
		}
		for port := low; port <= high; port++ {
			ports = append(ports, port)
		}
	}
	return ports
}

func numericPort(value interface{}) (int, bool) {
	switch v := value.(type) {
	case float64:
		return int(v), true
	case int:
		return v, true
	default:
		return 0, false
	}
}

func (l *ServiceRoleListener) closeRemovedServices(desired map[string][]int) {
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

func (l *ServiceRoleListener) ensureServiceListener(serviceName string, interceptPorts []int) {
	l.mu.Lock()
	_, exists := l.listeners[serviceName]
	l.mu.Unlock()
	if exists {
		return
	}
	listener, err := listenForServicePorts(l.ctx, serviceName, interceptPorts)
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
	return listenForServicePorts(ctx, serviceName, nil)
}

func listenForServicePorts(ctx ZitiContext, serviceName string, interceptPorts []int) (DataPlaneListener, error) {
	// Bind non-addressed: workload intercepts dial without dialOptions.identity,
	// and an identity-addressed terminator never matches an empty instanceId.
	listener, err := ctx.ListenWithOptions(serviceName, &ziti.ListenOptions{})
	if err != nil {
		return nil, fmt.Errorf("listen for ziti service %q: %w", serviceName, err)
	}
	return &namingListener{inner: NewListenerAdapter(listener), serviceName: serviceName, interceptPorts: interceptPorts}, nil
}

// namingListener stamps the accepted service's name and intercept ports on
// every connection; a connection arriving on private-<id> is routed by the
// name alone.
type namingListener struct {
	inner          DataPlaneListener
	serviceName    string
	interceptPorts []int
}

func (l *namingListener) Accept() (DataPlaneConn, error) {
	conn, err := l.inner.Accept()
	if err != nil {
		return nil, err
	}
	return &namedConn{DataPlaneConn: conn, serviceName: l.serviceName, interceptPorts: l.interceptPorts}, nil
}

func (l *namingListener) Close() error { return l.inner.Close() }

type namedConn struct {
	DataPlaneConn
	serviceName    string
	interceptPorts []int
}

func (c *namedConn) ServiceName() string { return c.serviceName }

func (c *namedConn) InterceptPorts() []int { return c.interceptPorts }

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
