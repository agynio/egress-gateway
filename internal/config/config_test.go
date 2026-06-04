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
	if cfg.RuleCacheTTL != defaultCacheTTL {
		t.Fatalf("rule cache ttl = %s", cfg.RuleCacheTTL)
	}
}

func TestLoadRejectsInvalidDuration(t *testing.T) {
	t.Setenv("RULE_CACHE_TTL", "nope")
	_, err := Load()
	if err == nil {
		t.Fatal("expected invalid duration to fail")
	}
}
