package rndc

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestConfigFromEnv(t *testing.T) {
	t.Setenv(EnvHost, "127.0.0.1")
	t.Setenv(EnvPort, "953")
	t.Setenv(EnvAlgorithm, "hmac-sha256")
	t.Setenv(EnvSecret, "dGVzdA==")
	t.Setenv(EnvTimeout, "5")
	t.Setenv(EnvMaxRetries, "2")
	t.Setenv(EnvRetryDelay, "0.1")

	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Host != "127.0.0.1" || cfg.Port != 953 || cfg.Algorithm != SHA256 {
		t.Fatalf("%+v", cfg)
	}
	if cfg.Secret != "dGVzdA==" || cfg.Timeout != 5*time.Second {
		t.Fatalf("%+v", cfg)
	}
	if cfg.MaxRetries != 2 || cfg.RetryDelay != 100*time.Millisecond {
		t.Fatalf("%+v", cfg)
	}
}

func TestConfigFromEnvMissing(t *testing.T) {
	for _, k := range []string{EnvHost, EnvPort, EnvAlgorithm, EnvSecret} {
		t.Setenv(k, "")
		_ = os.Unsetenv(k)
	}
	if _, err := ConfigFromEnv(); err == nil {
		t.Fatal("expected error")
	}
}

func TestParsePortInvalid(t *testing.T) {
	for _, p := range []string{"0", "70000", "not-a-port"} {
		if _, err := parsePortForTest(p); err == nil {
			t.Fatalf("expected error for %s", p)
		}
	}
}

func TestParseTimeoutInvalid(t *testing.T) {
	for _, p := range []string{"0", "-1", "not-a-timeout"} {
		if err := parseTimeoutForTest(p); err == nil {
			t.Fatalf("expected error for %s", p)
		}
	}
}

func TestConfigDotEnv(t *testing.T) {
	dir := t.TempDir()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })

	content := "RNDC_HOST=envhost\nRNDC_PORT=9953\nRNDC_ALGORITHM=sha256\nRNDC_SECRET=dGVzdA==\nRNDC_TIMEOUT=7\n"
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{EnvHost, EnvPort, EnvAlgorithm, EnvSecret, EnvTimeout} {
		_ = os.Unsetenv(k)
	}
	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Host != "envhost" || cfg.Port != 9953 || cfg.Timeout != 7*time.Second {
		t.Fatalf("%+v", cfg)
	}
}

func TestConfigValidate(t *testing.T) {
	cfg := Config{Host: "h", Port: 953, Algorithm: SHA256, Secret: "dGVzdA=="}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := Config{}
	if err := bad.Validate(); err == nil {
		t.Fatal("expected error")
	}
}
