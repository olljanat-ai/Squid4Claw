package config

import (
	"encoding/json"
	"os"
	"sync"
)

// RegistryConfig describes one upstream container registry to mirror.
type RegistryConfig struct {
	Name     string `json:"name"`     // e.g., "docker.io"
	Upstream string `json:"upstream"` // e.g., "https://registry-1.docker.io"
	Port     int    `json:"port"`     // e.g., 5000
}

// Config holds the main application configuration.
type Config struct {
	ListenAddr         string           `json:"listen_addr"`
	AdminAddr          string           `json:"admin_addr"`
	TransparentTLSAddr string           `json:"transparent_tls_addr"`
	DataDir            string           `json:"data_dir"`
	TLSCertFile        string           `json:"tls_cert_file"`
	TLSKeyFile         string           `json:"tls_key_file"`
	MaxLogEntries      int              `json:"max_log_entries"`
	Registries         []RegistryConfig `json:"registries"`
}

var (
	defaultConfig = Config{
		ListenAddr:         ":8080",
		AdminAddr:          ":443",
		TransparentTLSAddr: ":8443",
		DataDir:            "./data",
		MaxLogEntries:      10000,
	}
	current Config
	mu      sync.RWMutex
)

// Load reads config from a JSON file or returns defaults.
func Load(path string) (Config, error) {
	mu.Lock()
	defer mu.Unlock()

	current = defaultConfig
	if path == "" {
		return current, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return current, nil
		}
		return current, err
	}
	if err := json.Unmarshal(data, &current); err != nil {
		return current, err
	}
	return current, nil
}

// Get returns the current config.
func Get() Config {
	mu.RLock()
	defer mu.RUnlock()
	return current
}
