package config

import (
	"strings"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	t.Setenv("SAL_MASTER_KEY", strings.Repeat("ab", 32)) // 64 hex chars = 32 bytes
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.ListenAddr != ":8080" {
		t.Fatalf("listen = %q", c.ListenAddr)
	}
	if _, err := c.MasterKeyBytes(); err != nil {
		t.Fatal(err)
	}
}

func TestMasterKeyBadLength(t *testing.T) {
	t.Setenv("SAL_MASTER_KEY", "abcd")
	c, _ := Load()
	if _, err := c.MasterKeyBytes(); err == nil {
		t.Fatal("expected error for short key")
	}
}

func TestTLSCertRequiresKey(t *testing.T) {
	t.Setenv("SAL_TLS_CERT", "/tmp/cert.pem")
	if _, err := Load(); err == nil {
		t.Fatal("expected error when only cert set")
	}
	t.Setenv("SAL_TLS_KEY", "/tmp/key.pem")
	if _, err := Load(); err != nil {
		t.Fatalf("expected ok with both cert+key: %v", err)
	}
}
