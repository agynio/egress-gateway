package egress

import (
	"container/list"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"sync"
	"time"
)

type CertificateAuthority struct {
	cert        *x509.Certificate
	privateKey  any
	fingerprint string
}

func LoadCertificateAuthority(certPath string, keyPath string) (*CertificateAuthority, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read egress ca cert: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read egress ca key: %w", err)
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("decode egress ca cert: missing PEM block")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse egress ca cert: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("decode egress ca key: missing PEM block")
	}
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse egress ca key: %w", err)
	}
	fingerprintBytes := sha256.Sum256(cert.Raw)
	return &CertificateAuthority{cert: cert, privateKey: key, fingerprint: hex.EncodeToString(fingerprintBytes[:])}, nil
}

type LeafCertificateCache struct {
	ca       *CertificateAuthority
	clock    Clock
	ttl      time.Duration
	capacity int
	mu       sync.Mutex
	items    map[string]*list.Element
	order    *list.List
}

type leafEntry struct {
	key       string
	cert      *tls.Certificate
	expiresAt time.Time
}

func NewLeafCertificateCache(ca *CertificateAuthority, ttl time.Duration, capacity int, clock Clock) *LeafCertificateCache {
	if ca == nil {
		panic("certificate authority is required")
	}
	if ttl <= 0 {
		panic("leaf certificate ttl must be positive")
	}
	if capacity <= 0 {
		panic("leaf certificate cache capacity must be positive")
	}
	if clock == nil {
		panic("clock is required")
	}
	return &LeafCertificateCache{ca: ca, ttl: ttl, capacity: capacity, clock: clock, items: map[string]*list.Element{}, order: list.New()}
}

func (c *LeafCertificateCache) Certificate(host string) (*tls.Certificate, error) {
	key := c.ca.fingerprint + ":" + host
	now := c.clock.Now()
	c.mu.Lock()
	if element, ok := c.items[key]; ok {
		entry := element.Value.(*leafEntry)
		if now.Before(entry.expiresAt) {
			c.order.MoveToFront(element)
			cert := entry.cert
			c.mu.Unlock()
			return cert, nil
		}
		c.order.Remove(element)
		delete(c.items, key)
	}
	c.mu.Unlock()

	cert, err := c.generate(host, now)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.items[key] = c.order.PushFront(&leafEntry{key: key, cert: cert, expiresAt: now.Add(c.ttl)})
	for len(c.items) > c.capacity {
		oldest := c.order.Back()
		entry := oldest.Value.(*leafEntry)
		delete(c.items, entry.key)
		c.order.Remove(oldest)
	}
	c.mu.Unlock()
	return cert, nil
}

func (c *LeafCertificateCache) generate(host string, now time.Time) (*tls.Certificate, error) {
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, fmt.Errorf("generate leaf serial: %w", err)
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(c.ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, c.ca.cert, privateKey.Public(), c.ca.privateKey)
	if err != nil {
		return nil, fmt.Errorf("sign leaf certificate: %w", err)
	}
	return &tls.Certificate{Certificate: [][]byte{der, c.ca.cert.Raw}, PrivateKey: privateKey, Leaf: template}, nil
}
