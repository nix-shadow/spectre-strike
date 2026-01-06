package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Config represents the global configuration
type Config struct {
	General  GeneralConfig  `json:"general"`
	Attack   AttackConfig   `json:"attack"`
	Proxy    ProxyConfig    `json:"proxy"`
	Advanced AdvancedConfig `json:"advanced"`
	API      APIConfig      `json:"api"`
}

// GeneralConfig contains general settings
type GeneralConfig struct {
	LogLevel     string `json:"log_level"`
	OutputDir    string `json:"output_dir"`
	ReportFormat string `json:"report_format"` // json, html, both
	Verbose      bool   `json:"verbose"`
}

// AttackConfig contains default attack settings
type AttackConfig struct {
	DefaultDuration int      `json:"default_duration"` // seconds
	DefaultThreads  int      `json:"default_threads"`
	DefaultRPS      int      `json:"default_rps"`
	UseIntelligence bool     `json:"use_intelligence"`
	AutoAdapt       bool     `json:"auto_adapt"`
	Vectors         []string `json:"vectors"`
	MaxRetries      int      `json:"max_retries"`
}

// ProxyConfig contains proxy settings
type ProxyConfig struct {
	Enabled        bool   `json:"enabled"`
	ProxyFile      string `json:"proxy_file"`
	RotationMode   string `json:"rotation_mode"` // round-robin, random, sticky
	HealthCheck    bool   `json:"health_check"`
	HealthCheckURL string `json:"health_check_url"`
	MaxFailures    int    `json:"max_failures"`
	RotateInterval int    `json:"rotate_interval"` // seconds
}

// AdvancedConfig contains advanced settings
type AdvancedConfig struct {
	WAFBypass           bool     `json:"waf_bypass"`
	TLSFingerprinting   bool     `json:"tls_fingerprinting"`
	AntiBot             bool     `json:"anti_bot"`
	HeaderRandomization bool     `json:"header_randomization"`
	EvasionStrategy     string   `json:"evasion_strategy"` // aggressive, balanced, stealth, human-like
	CustomHeaders       []string `json:"custom_headers"`
	PayloadTemplates    []string `json:"payload_templates"`
	DNSResolution       string   `json:"dns_resolution"` // system, custom, doh
	CustomDNS           []string `json:"custom_dns"`
}

// APIConfig contains API server settings
type APIConfig struct {
	Enabled bool   `json:"enabled"`
	Port    int    `json:"port"`
	APIKey  string `json:"api_key"`
	CORS    bool   `json:"cors"`
}

// DefaultConfig returns the default configuration
func DefaultConfig() *Config {
	return &Config{
		General: GeneralConfig{
			LogLevel:     "info",
			OutputDir:    "./reports",
			ReportFormat: "both",
			Verbose:      false,
		},
		Attack: AttackConfig{
			DefaultDuration: 60,
			DefaultThreads:  10,
			DefaultRPS:      100,
			UseIntelligence: true,
			AutoAdapt:       true,
			Vectors:         []string{"adaptive", "http2", "post"},
			MaxRetries:      3,
		},
		Proxy: ProxyConfig{
			Enabled:        false,
			ProxyFile:      "proxies.txt",
			RotationMode:   "random",
			HealthCheck:    true,
			HealthCheckURL: "https://httpbin.org/ip",
			MaxFailures:    5,
			RotateInterval: 30,
		},
		Advanced: AdvancedConfig{
			WAFBypass:           true,
			TLSFingerprinting:   true,
			AntiBot:             true,
			HeaderRandomization: true,
			EvasionStrategy:     "balanced",
			CustomHeaders:       []string{},
			PayloadTemplates:    []string{},
			DNSResolution:       "system",
			CustomDNS:           []string{"8.8.8.8", "1.1.1.1"},
		},
		API: APIConfig{
			Enabled: false,
			Port:    8080,
			APIKey:  "",
			CORS:    true,
		},
	}
}

// LoadFromFile loads configuration from a JSON file
func LoadFromFile(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	config := DefaultConfig()
	if err := json.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %v", err)
	}

	return config, nil
}

// SaveToFile saves configuration to a JSON file
func (c *Config) SaveToFile(filename string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %v", err)
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %v", err)
	}

	return nil
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.Attack.DefaultDuration <= 0 {
		return fmt.Errorf("attack duration must be positive")
	}

	if c.Attack.DefaultThreads <= 0 {
		return fmt.Errorf("threads must be positive")
	}

	if c.Attack.DefaultRPS <= 0 {
		return fmt.Errorf("RPS must be positive")
	}

	if c.Proxy.Enabled && c.Proxy.ProxyFile == "" {
		return fmt.Errorf("proxy file must be specified when proxies are enabled")
	}

	if c.API.Enabled && c.API.Port <= 0 {
		return fmt.Errorf("API port must be positive")
	}

	validEvasions := map[string]bool{
		"aggressive": true,
		"balanced":   true,
		"stealth":    true,
		"human-like": true,
	}
	if !validEvasions[c.Advanced.EvasionStrategy] {
		return fmt.Errorf("invalid evasion strategy: %s", c.Advanced.EvasionStrategy)
	}

	return nil
}

// GetDuration returns the attack duration as time.Duration
func (c *Config) GetDuration() time.Duration {
	return time.Duration(c.Attack.DefaultDuration) * time.Second
}

// GetRotateInterval returns the proxy rotation interval as time.Duration
func (c *Config) GetRotateInterval() time.Duration {
	return time.Duration(c.Proxy.RotateInterval) * time.Second
}
