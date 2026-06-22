package main

import (
	"testing"
	"time"
)

func TestDefaultRunTimeoutIsOneMinute(t *testing.T) {
	cfg := defaultConfig()
	if cfg.RunTimeout != time.Minute {
		t.Fatalf("default RunTimeout = %s, want %s", cfg.RunTimeout, time.Minute)
	}
}

func TestNormalizeRunTimeoutDefaultsToOneMinute(t *testing.T) {
	cfg := defaultConfig()
	cfg.RunTimeout = 0
	cfg.normalize()
	if cfg.RunTimeout != time.Minute {
		t.Fatalf("normalized RunTimeout = %s, want %s", cfg.RunTimeout, time.Minute)
	}

	cfg.RunTimeout = -1 * time.Second
	cfg.normalize()
	if cfg.RunTimeout != time.Minute {
		t.Fatalf("normalized negative RunTimeout = %s, want %s", cfg.RunTimeout, time.Minute)
	}
}

func TestExplicitRunTimeoutConfigOverridesDefault(t *testing.T) {
	cfg := defaultConfig()
	if err := applyConfigYAML(&cfg, []byte("run_timeout_seconds: 90\n")); err != nil {
		t.Fatal(err)
	}
	cfg.normalize()
	if cfg.RunTimeout != 90*time.Second {
		t.Fatalf("configured RunTimeout = %s, want %s", cfg.RunTimeout, 90*time.Second)
	}
}
