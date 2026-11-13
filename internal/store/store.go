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

// migrations 按序递增的 schema 迁移；PRAGMA user_version 记录已应用步数。
// 已发布的版本不可修改，只能追加。
var migrations = []string{
	// v1: 初始 schema（历史版本的 CREATE TABLE IF NOT EXISTS 等价物）。
	`CREATE TABLE IF NOT EXISTS servers (
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
);`,
	// v2: 账户到期时间（RFC3339，空串 = 永不到期）。
	`ALTER TABLE accounts ADD COLUMN expires_at TEXT NOT NULL DEFAULT '';`,
	// v3: 移除从未投入使用的 settings 表（死代码清理）。
	`DROP TABLE IF EXISTS settings;`,
}

func (s *Store) migrate() error {
	var version int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	for i := version; i < len(migrations); i++ {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[i]); err != nil {
			tx.Rollback()
			return err
		}
		// user_version 不能用参数绑定，i+1 由循环变量构成、无注入面。
		if _, err := tx.Exec("PRAGMA user_version = " + itoa(i+1)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// mkdirAll 供测试建旧版数据目录复用。
func mkdirAll(path string) error { return os.MkdirAll(filepath.Dir(path), 0o700) }
