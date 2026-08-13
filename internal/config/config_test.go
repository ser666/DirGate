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
	if c.PermissionBackend != "acl" {
		t.Fatalf("backend = %q", c.PermissionBackend)
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

func TestBackendInvalid(t *testing.T) {
	t.Setenv("SAL_PERMISSION_BACKEND", "bogus")
	if _, err := Load(); err == nil {
		t.Fatal("expected error for bad backend")
	}
}
