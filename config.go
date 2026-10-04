package rndc

import (
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

// Environment variable names used by ConfigFromEnv and the CLI.
const (
	EnvHost       = "RNDC_HOST"
	EnvPort       = "RNDC_PORT"
	EnvAlgorithm  = "RNDC_ALGORITHM"
	EnvSecret     = "RNDC_SECRET"
	EnvTimeout    = "RNDC_TIMEOUT"
	EnvMaxRetries = "RNDC_MAX_RETRIES"
	EnvRetryDelay = "RNDC_RETRY_DELAY"
)

const (
	// DefaultTimeout is used when Config.Timeout is unset.
	DefaultTimeout = 10 * time.Second
	// DefaultMaxRetries is used when Config.MaxRetries is unset.
	DefaultMaxRetries = 3
	// DefaultRetryDelay is used when Config.RetryDelay is unset.
	DefaultRetryDelay = time.Second
)

// Config holds connection settings for an RNDC client.
type Config struct {
	Host       string
	Port       int
	Algorithm  Algorithm
	Secret     string // Base64-encoded key, as in named.conf.
	Timeout    time.Duration
	MaxRetries int
	RetryDelay time.Duration
}

// ConfigFromEnv loads configuration from RNDC_* environment variables.
// A .env file in the current directory is loaded first if present.
func ConfigFromEnv() (Config, error) {
	_ = godotenv.Load()
	cfg := Config{
		Timeout:    DefaultTimeout,
		MaxRetries: DefaultMaxRetries,
		RetryDelay: DefaultRetryDelay,
	}
	host, err := requiredEnv(EnvHost)
	if err != nil {
		return Config{}, err
	}
	cfg.Host = host

	portStr, err := requiredEnv(EnvPort)
	if err != nil {
		return Config{}, err
	}
	cfg.Port, err = parsePort(portStr)
	if err != nil {
		return Config{}, err
	}

	algoStr, err := requiredEnv(EnvAlgorithm)
	if err != nil {
		return Config{}, err
	}
	cfg.Algorithm, err = ParseAlgorithm(algoStr)
	if err != nil {
		return Config{}, err
	}

	secret, err := requiredEnv(EnvSecret)
	if err != nil {
		return Config{}, err
	}
	cfg.Secret = secret

	if v, ok := os.LookupEnv(EnvTimeout); ok && v != "" {
		cfg.Timeout, err = parseTimeout(v)
		if err != nil {
			return Config{}, err
		}
	}
	if v, ok := os.LookupEnv(EnvMaxRetries); ok && v != "" {
		cfg.MaxRetries, err = parseIntEnv(EnvMaxRetries, v)
		if err != nil {
			return Config{}, err
		}
	}
	if v, ok := os.LookupEnv(EnvRetryDelay); ok && v != "" {
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return Config{}, fmt.Errorf("invalid float value for %s: %s", EnvRetryDelay, v)
		}
		cfg.RetryDelay = time.Duration(f * float64(time.Second))
	}
	return cfg, nil
}

// Validate reports whether required fields are set and internally consistent.
func (c Config) Validate() error {
	if c.Host == "" {
		return fmt.Errorf("host is required (provide it or set %s)", EnvHost)
	}
	if c.Port == 0 {
		return fmt.Errorf("port is required (provide it or set %s)", EnvPort)
	}
	if _, err := parsePort(strconv.Itoa(c.Port)); err != nil {
		return err
	}
	if !c.Algorithm.valid() {
		return fmt.Errorf("algorithm is required (provide it or set %s)", EnvAlgorithm)
	}
	if c.Secret == "" {
		return fmt.Errorf("secret is required (provide it or set %s)", EnvSecret)
	}
	if _, err := base64.StdEncoding.DecodeString(c.Secret); err != nil {
		if _, err2 := decodeSecret(c.Secret); err2 != nil {
			return fmt.Errorf("invalid secret key format: %w", err)
		}
	}
	if c.Timeout < 0 {
		return fmt.Errorf("timeout must be positive")
	}
	if c.RetryDelay < 0 {
		return fmt.Errorf("retry delay must not be negative")
	}
	return nil
}

func (c Config) withDefaults() Config {
	if c.Timeout <= 0 {
		c.Timeout = DefaultTimeout
	}
	if c.MaxRetries <= 0 {
		c.MaxRetries = DefaultMaxRetries
	}
	if c.RetryDelay == 0 {
		c.RetryDelay = DefaultRetryDelay
	}
	return c
}

func (c Config) decodedSecret() ([]byte, error) {
	return decodeSecret(c.Secret)
}

func decodeSecret(s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}

func requiredEnv(key string) (string, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return "", fmt.Errorf("required environment variable %s is not set", key)
	}
	return v, nil
}

func parsePort(s string) (int, error) {
	port, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid port number: %s", s)
	}
	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("port must be between 1 and 65535, got %d", port)
	}
	return port, nil
}

func parseTimeout(s string) (time.Duration, error) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid timeout value: %s", s)
	}
	if n <= 0 {
		return 0, fmt.Errorf("timeout must be positive, got %d", n)
	}
	return time.Duration(n) * time.Second, nil
}

func parseIntEnv(key, v string) (int, error) {
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("invalid integer value for %s: %s", key, v)
	}
	return n, nil
}
