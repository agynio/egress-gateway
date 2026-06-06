package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

const (
	defaultGRPCAddress          = ":50051"
	defaultEgressTarget         = "egress:50051"
	defaultSecretsTarget        = "secrets:50051"
	defaultNotificationsTarget  = "notifications:50051"
	defaultMeteringTarget       = "metering:50051"
	defaultTracingTarget        = "tracing:50051"
	defaultAgentsTarget         = "agents:50051"
	defaultZitiManagementTarget = "ziti-management:50051"
	defaultZitiIdentityFile     = "/var/lib/ziti/identity.json"
	defaultZitiServiceName      = ""
	defaultEgressCACertPath     = "/var/run/agyn/egress-ca/tls.crt"
	defaultEgressCAKeyPath      = "/var/run/agyn/egress-ca/tls.key"
	defaultRuleCacheTTL         = 15 * time.Second
	defaultSecretCacheTTL       = 60 * time.Second
	defaultLeafCertTTL          = 10 * time.Minute
	defaultLeafCertCacheSize    = 4096
	defaultForwardTimeout       = 30 * time.Second
)

type Config struct {
	GRPCAddress           string
	EgressAddress         string
	SecretsAddress        string
	NotificationsAddress  string
	MeteringAddress       string
	TracingAddress        string
	AgentsAddress         string
	ZitiManagementAddress string
	ZitiIdentityFile      string
	ZitiServiceName       string
	EgressCACertPath      string
	EgressCAKeyPath       string
	RuleCacheTTL          time.Duration
	SecretCacheTTL        time.Duration
	LeafCertTTL           time.Duration
	LeafCertCacheSize     int
	ForwardTimeout        time.Duration
}

func Load() (Config, error) {
	cfg := Config{
		GRPCAddress:           envOrDefault("GRPC_ADDRESS", defaultGRPCAddress),
		EgressAddress:         envOrDefault("EGRESS_ADDRESS", defaultEgressTarget),
		SecretsAddress:        envOrDefault("SECRETS_SERVICE_ADDRESS", defaultSecretsTarget),
		NotificationsAddress:  envOrDefault("NOTIFICATIONS_ADDRESS", defaultNotificationsTarget),
		MeteringAddress:       envOrDefault("METERING_ADDRESS", defaultMeteringTarget),
		TracingAddress:        envOrDefault("TRACING_ADDRESS", defaultTracingTarget),
		AgentsAddress:         envOrDefault("AGENTS_SERVICE_ADDRESS", defaultAgentsTarget),
		ZitiManagementAddress: envOrDefault("ZITI_MANAGEMENT_ADDRESS", defaultZitiManagementTarget),
		ZitiIdentityFile:      envOrDefault("ZITI_IDENTITY_FILE", defaultZitiIdentityFile),
		ZitiServiceName:       envOrDefault("ZITI_SERVICE_NAME", defaultZitiServiceName),
		EgressCACertPath:      envOrDefault("EGRESS_CA_CERT_PATH", defaultEgressCACertPath),
		EgressCAKeyPath:       envOrDefault("EGRESS_CA_KEY_PATH", defaultEgressCAKeyPath),
		RuleCacheTTL:          defaultRuleCacheTTL,
		SecretCacheTTL:        defaultSecretCacheTTL,
		LeafCertTTL:           defaultLeafCertTTL,
		LeafCertCacheSize:     defaultLeafCertCacheSize,
		ForwardTimeout:        defaultForwardTimeout,
	}
	var err error
	cfg.RuleCacheTTL, err = durationEnvOrDefault("RULE_CACHE_TTL", cfg.RuleCacheTTL)
	if err != nil {
		return Config{}, err
	}
	cfg.SecretCacheTTL, err = durationEnvOrDefault("SECRET_CACHE_TTL", cfg.SecretCacheTTL)
	if err != nil {
		return Config{}, err
	}
	cfg.LeafCertTTL, err = durationEnvOrDefault("LEAF_CERT_TTL", cfg.LeafCertTTL)
	if err != nil {
		return Config{}, err
	}
	cfg.ForwardTimeout, err = durationEnvOrDefault("FORWARD_TIMEOUT", cfg.ForwardTimeout)
	if err != nil {
		return Config{}, err
	}
	cfg.LeafCertCacheSize, err = intEnvOrDefault("LEAF_CERT_CACHE_SIZE", cfg.LeafCertCacheSize)
	if err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func envOrDefault(key string, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}

func durationEnvOrDefault(key string, fallback time.Duration) (time.Duration, error) {
	value := os.Getenv(key)
	if value == "" {
		return fallback, nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", key, err)
	}
	if duration <= 0 {
		return 0, fmt.Errorf("%s must be positive", key)
	}
	return duration, nil
}

func intEnvOrDefault(key string, fallback int) (int, error) {
	value := os.Getenv(key)
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", key, err)
	}
	if parsed <= 0 {
		return 0, fmt.Errorf("%s must be positive", key)
	}
	return parsed, nil
}
