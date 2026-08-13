package store

import (
	"path/filepath"
	"testing"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	key := make([]byte, 32)
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "test.db"), key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestOpenAndMigrateIdempotent(t *testing.T) {
	s := newTestStore(t)
	var n int
	if err := s.db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('servers','accounts','directory_permissions','admin','settings')`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 5 {
		t.Fatalf("expected 5 tables, got %d", n)
	}
}

func TestEncryptDecrypt(t *testing.T) {
	s := newTestStore(t)
	ct, err := s.Encrypt([]byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := s.Decrypt(ct)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "pw" {
		t.Fatalf("got %q", pt)
	}
}
