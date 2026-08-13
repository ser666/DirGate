package store

import (
	"database/sql"
	"os"
	"path/filepath"

	crypto "serveragentlink/internal/crypto"

	_ "modernc.org/sqlite"
)

type Store struct {
	db  *sql.DB
	key []byte
}

func Open(dataDir string, key []byte) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	dsn := "file:" + filepath.Join(dataDir, "server-agent-link.db") + "?_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	s := &Store{db: db, key: key}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) Encrypt(plain []byte) ([]byte, error) { return crypto.Encrypt(s.key, plain) }
func (s *Store) Decrypt(enc []byte) ([]byte, error)   { return crypto.Decrypt(s.key, enc) }

func (s *Store) migrate() error {
	const schema = `
CREATE TABLE IF NOT EXISTS servers (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, host TEXT NOT NULL,
  ssh_port INTEGER NOT NULL DEFAULT 22, root_user TEXT NOT NULL DEFAULT 'root',
  root_password_enc BLOB NOT NULL, host_key TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 1, last_verified_at TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS accounts (
  id TEXT PRIMARY KEY, server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  username TEXT NOT NULL, password_enc BLOB NOT NULL,
  coding_capable INTEGER NOT NULL DEFAULT 0, exposed_to_agent INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'pending', last_error TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  UNIQUE(server_id, username)
);
CREATE TABLE IF NOT EXISTS directory_permissions (
  id TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  path TEXT NOT NULL, mode TEXT NOT NULL, UNIQUE(account_id, path)
);
CREATE TABLE IF NOT EXISTS admin (
  id INTEGER PRIMARY KEY CHECK (id = 1), username TEXT NOT NULL, password_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
`
	_, err := s.db.Exec(schema)
	return err
}
