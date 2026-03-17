// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/BurntSushi/toml"
)

type ServerConfig struct {
	ConfigDir             string  `toml:"-"`
	ConfigPath            string  `toml:"-"`
	UDPHost               string  `toml:"UDP_HOST"`
	UDPPort               int     `toml:"UDP_PORT"`
	UDPReaders            int     `toml:"UDP_READERS"`
	SocketBufferSize      int     `toml:"SOCKET_BUFFER_SIZE"`
	MaxConcurrentRequests int     `toml:"MAX_CONCURRENT_REQUESTS"`
	DNSRequestWorkers     int     `toml:"DNS_REQUEST_WORKERS"`
	MaxPacketSize         int     `toml:"MAX_PACKET_SIZE"`
	DropLogIntervalSecs   float64 `toml:"DROP_LOG_INTERVAL_SECONDS"`
	DataEncryptionMethod  int     `toml:"DATA_ENCRYPTION_METHOD"`
	EncryptionKeyFile     string  `toml:"ENCRYPTION_KEY_FILE"`
	LogLevel              string  `toml:"LOG_LEVEL"`
}

func defaultServerConfig() ServerConfig {
	workers := runtime.NumCPU()
	if workers < 1 {
		workers = 1
	}
	if workers > 16 {
		workers = 16
	}

	readers := runtime.NumCPU() / 2
	if readers < 1 {
		readers = 1
	}
	if readers > 4 {
		readers = 4
	}

	return ServerConfig{
		UDPHost:               "0.0.0.0",
		UDPPort:               53,
		UDPReaders:            readers,
		SocketBufferSize:      8 * 1024 * 1024,
		MaxConcurrentRequests: 4096,
		DNSRequestWorkers:     workers,
		MaxPacketSize:         65535,
		DropLogIntervalSecs:   2.0,
		DataEncryptionMethod:  1,
		EncryptionKeyFile:     "encrypt_key.txt",
		LogLevel:              "INFO",
	}
}

func LoadServerConfig(filename string) (ServerConfig, error) {
	cfg := defaultServerConfig()
	path, err := filepath.Abs(filename)
	if err != nil {
		return cfg, err
	}

	if _, err := os.Stat(path); err != nil {
		return cfg, fmt.Errorf("config file not found: %s", path)
	}

	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return cfg, fmt.Errorf("parse TOML failed for %s: %w", path, err)
	}

	cfg.ConfigPath = path
	cfg.ConfigDir = filepath.Dir(path)

	if cfg.UDPHost == "" {
		cfg.UDPHost = "0.0.0.0"
	}
	if cfg.UDPPort <= 0 || cfg.UDPPort > 65535 {
		return cfg, fmt.Errorf("invalid UDP_PORT: %d", cfg.UDPPort)
	}
	if cfg.UDPReaders <= 0 {
		cfg.UDPReaders = defaultServerConfig().UDPReaders
	}
	if cfg.SocketBufferSize <= 0 {
		cfg.SocketBufferSize = 8 * 1024 * 1024
	}
	if cfg.MaxConcurrentRequests <= 0 {
		cfg.MaxConcurrentRequests = 4096
	}
	if cfg.DNSRequestWorkers <= 0 {
		cfg.DNSRequestWorkers = defaultServerConfig().DNSRequestWorkers
	}
	if cfg.MaxPacketSize <= 0 {
		cfg.MaxPacketSize = 65535
	}
	if cfg.DropLogIntervalSecs <= 0 {
		cfg.DropLogIntervalSecs = 2.0
	}
	if cfg.DataEncryptionMethod < 0 || cfg.DataEncryptionMethod > 5 {
		cfg.DataEncryptionMethod = 1
	}
	if cfg.EncryptionKeyFile == "" {
		cfg.EncryptionKeyFile = "encrypt_key.txt"
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "INFO"
	}

	return cfg, nil
}

func (c ServerConfig) Address() string {
	return fmt.Sprintf("%s:%d", c.UDPHost, c.UDPPort)
}

func (c ServerConfig) DropLogInterval() time.Duration {
	return time.Duration(c.DropLogIntervalSecs * float64(time.Second))
}

func (c ServerConfig) EncryptionKeyPath() string {
	if c.EncryptionKeyFile == "" {
		return filepath.Join(c.ConfigDir, "encrypt_key.txt")
	}
	if filepath.IsAbs(c.EncryptionKeyFile) {
		return c.EncryptionKeyFile
	}
	return filepath.Join(c.ConfigDir, c.EncryptionKeyFile)
}
