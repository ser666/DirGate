package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "data"), []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func userVersion(t *testing.T, s *Store) int {
	t.Helper()
	var v int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

// 旧库（无 user_version、无 expires_at 列）升级后须可用且数据保留。
func TestMigrateLegacyDB(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "data", "server-agent-link.db")
	if err := openRawDB(dbPath); err != nil {
		t.Fatal(err)
	}
	s, err := Open(filepath.Join(dir, "data"), []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if v := userVersion(t, s); v != len(migrations) {
		t.Fatalf("user_version = %d, want %d", v, len(migrations))
	}
	// 旧数据仍可读写，且新列带默认值。
	got, err := s.GetAccount(context.Background(), "acc1")
	if err != nil {
		t.Fatal(err)
	}
	if got.ExpiresAt != "" {
		t.Fatalf("legacy account expires_at = %q, want empty", got.ExpiresAt)
	}
}

// ListExpiringAccounts 返回到期未锁定的账户，锁定后不再重复返回。
func TestListExpiringAccounts(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	sv, _ := s.CreateServer(ctx, "s1", "10.0.0.1", 22, "root", "rp")
	a, _ := s.CreateAccount(ctx, sv.ID, "alice", "pw", true, true)
	b, _ := s.CreateAccount(ctx, sv.ID, "bob", "pw", true, true)
	a.ExpiresAt = "2026-01-01T00:00:00Z"
	_ = s.UpdateAccount(ctx, *a)
	b.ExpiresAt = "2030-01-01T00:00:00Z"
	_ = s.UpdateAccount(ctx, *b)

	exp, err := s.ListExpiringAccounts(ctx, "2026-06-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if len(exp) != 1 || exp[0].Username != "alice" {
		t.Fatalf("expiring = %+v", exp)
	}
	if err := s.MarkAccountLocked(ctx, a.ID, "expired"); err != nil {
		t.Fatal(err)
	}
	exp, _ = s.ListExpiringAccounts(ctx, "2026-06-01T00:00:00Z")
	if len(exp) != 0 {
		t.Fatalf("locked account must not reappear: %+v", exp)
	}
}

func TestMigrateFreshDBSchemaVersion(t *testing.T) {
	s := newTestStore(t)
	if v := userVersion(t, s); v != len(migrations) {
		t.Fatalf("user_version = %d, want %d", v, len(migrations))
	}
}

// openRawDB 建一个 v0 旧库：初始 schema（无 expires_at、含 settings 表）。
func openRawDB(path string) error {
	if err := mkdirAll(path); err != nil {
		return err
	}
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		return err
	}
	defer db.Close()
	const legacy = `
CREATE TABLE servers (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, host TEXT NOT NULL,
  ssh_port INTEGER NOT NULL DEFAULT 22, root_user TEXT NOT NULL DEFAULT 'root',
  root_password_enc BLOB NOT NULL, host_key TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 1, last_verified_at TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE accounts (
  id TEXT PRIMARY KEY, server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  username TEXT NOT NULL, password_enc BLOB NOT NULL,
  coding_capable INTEGER NOT NULL DEFAULT 0, exposed_to_agent INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'pending', last_error TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  UNIQUE(server_id, username)
);
CREATE TABLE directory_permissions (
  id TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  path TEXT NOT NULL, mode TEXT NOT NULL, UNIQUE(account_id, path)
);
CREATE TABLE admin (id INTEGER PRIMARY KEY CHECK (id = 1), username TEXT NOT NULL, password_hash TEXT NOT NULL);
CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
INSERT INTO servers (id,name,host,ssh_port,root_user,root_password_enc,host_key,enabled,last_verified_at,created_at,updated_at)
  VALUES ('srv1','old','10.0.0.1',22,'root',x'00','','1','','t0','t0');
INSERT INTO accounts (id,server_id,username,password_enc,coding_capable,exposed_to_agent,status,last_error,created_at,updated_at)
  VALUES ('acc1','srv1','legacy',x'00',0,0,'active','','t0','t0');
`
	_, err = db.Exec(legacy)
	return err
}
