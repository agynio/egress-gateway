package config

import "testing"

func TestLoadDefaults(t *testing.T) {
	t.Setenv("GRPC_ADDRESS", "")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.GRPCAddress != defaultGRPCAddress {
		t.Fatalf("grpc address = %q", cfg.GRPCAddress)
	}
	if cfg.EgressAddress != defaultEgressTarget {
		t.Fatalf("egress address = %q", cfg.EgressAddress)
	}
	if cfg.RuleCacheTTL != defaultRuleCacheTTL {
		t.Fatalf("rule cache ttl = %s", cfg.RuleCacheTTL)
	}
	if cfg.SecretCacheTTL != defaultSecretCacheTTL {
		t.Fatalf("secret cache ttl = %s", cfg.SecretCacheTTL)
	}
	if cfg.ZitiEnrollmentJWTFile != defaultZitiEnrollmentJWT {
		t.Fatalf("ziti enrollment jwt file = %q", cfg.ZitiEnrollmentJWTFile)
	}
	if cfg.ZitiServiceName != defaultZitiServiceName {
		t.Fatalf("ziti service name = %q", cfg.ZitiServiceName)
	}
	if cfg.LeafCertCacheSize != defaultLeafCertCacheSize {
		t.Fatalf("leaf cert cache size = %d", cfg.LeafCertCacheSize)
	}
	if cfg.DataPlaneRetryInterval != defaultDataPlaneRetry {
		t.Fatalf("data-plane retry interval = %s", cfg.DataPlaneRetryInterval)
	}
}

func TestLoadRejectsInvalidDuration(t *testing.T) {
	t.Setenv("RULE_CACHE_TTL", "nope")
	_, err := Load()
	if err == nil {
		t.Fatal("expected invalid duration to fail")
	}
}

func TestLoadRejectsInvalidLeafCertCacheSize(t *testing.T) {
	t.Setenv("LEAF_CERT_CACHE_SIZE", "0")
	_, err := Load()
	if err == nil {
		t.Fatal("expected invalid cache size to fail")
	}
}

func TestLoadReadsZitiEnrollmentJWTFile(t *testing.T) {
	t.Setenv("ZITI_ENROLLMENT_JWT_FILE", "/var/run/secrets/ziti/enrollmentJwt")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ZitiEnrollmentJWTFile != "/var/run/secrets/ziti/enrollmentJwt" {
		t.Fatalf("ziti enrollment jwt file = %q", cfg.ZitiEnrollmentJWTFile)
	}
}
