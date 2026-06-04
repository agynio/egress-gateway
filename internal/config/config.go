package config

import (
	"fmt"
	"os"
	"time"
)

const (
	defaultGRPCAddress         = ":50051"
	defaultEgressRulesTarget   = "egress-rules:50051"
	defaultSecretsTarget       = "secrets:50051"
	defaultNotificationsTarget = "notifications:50051"
	defaultMeteringTarget      = "metering:50051"
	defaultTracingTarget       = "tracing:50051"
	defaultZitiIdentityFile    = "/var/lib/ziti/identity.json"
	defaultEgressCACertFile    = "/var/lib/egress-ca/tls.crt"
	defaultEgressCAKeyFile     = "/var/lib/egress-ca/tls.key"
	defaultCacheTTL            = 15 * time.Second
)

type Config struct {
	GRPCAddress          string
	EgressRulesAddress   string
	SecretsAddress       string
	NotificationsAddress string
	MeteringAddress      string
	TracingAddress       string
	ZitiIdentityFile     string
	EgressCACertFile     string
	EgressCAKeyFile      string
	RuleCacheTTL         time.Duration
	SecretCacheTTL       time.Duration
}

func Load() (Config, error) {
	cfg := Config{
		GRPCAddress:          envOrDefault("GRPC_ADDRESS", defaultGRPCAddress),
		EgressRulesAddress:   envOrDefault("EGRESS_RULES_ADDRESS", defaultEgressRulesTarget),
		SecretsAddress:       envOrDefault("SECRETS_SERVICE_ADDRESS", defaultSecretsTarget),
		NotificationsAddress: envOrDefault("NOTIFICATIONS_ADDRESS", defaultNotificationsTarget),
		MeteringAddress:      envOrDefault("METERING_ADDRESS", defaultMeteringTarget),
		TracingAddress:       envOrDefault("TRACING_ADDRESS", defaultTracingTarget),
		ZitiIdentityFile:     envOrDefault("ZITI_IDENTITY_FILE", defaultZitiIdentityFile),
		EgressCACertFile:     envOrDefault("EGRESS_CA_CERT_FILE", defaultEgressCACertFile),
		EgressCAKeyFile:      envOrDefault("EGRESS_CA_KEY_FILE", defaultEgressCAKeyFile),
		RuleCacheTTL:         defaultCacheTTL,
		SecretCacheTTL:       defaultCacheTTL,
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
