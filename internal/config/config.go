package config

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
)

type Config struct {
	ListenAddr    string
	DataDir       string
	MasterKeyHex  string
	MCPToken      string
	AdminUser     string
	AdminPassword string
	TLSCert       string
	TLSKey        string
}

func Load() (*Config, error) {
	if err := LoadDotEnv(); err != nil {
		return nil, fmt.Errorf("load .env: %w", err)
	}
	c := &Config{
		ListenAddr:    getenv("DG_LISTEN_ADDR", ":8080"),
		DataDir:       getenv("DG_DATA_DIR", "./data"),
		MasterKeyHex:  os.Getenv("DG_MASTER_KEY"),
		MCPToken:      os.Getenv("DG_MCP_TOKEN"),
		AdminUser:     getenv("DG_ADMIN_USER", "admin"),
		AdminPassword: os.Getenv("DG_ADMIN_PASSWORD"),
		TLSCert:       os.Getenv("DG_TLS_CERT"),
		TLSKey:        os.Getenv("DG_TLS_KEY"),
	}
	if (c.TLSCert == "") != (c.TLSKey == "") {
		return nil, errors.New("DG_TLS_CERT and DG_TLS_KEY must be set together")
	}
	return c, nil
}

func (c *Config) MasterKeyBytes() ([]byte, error) {
	if c.MasterKeyHex == "" {
		return nil, errors.New("master key not set")
	}
	b, err := hex.DecodeString(c.MasterKeyHex)
	if err != nil || len(b) != 32 {
		return nil, errors.New("master key must be 32 bytes hex-encoded")
	}
	return b, nil
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
