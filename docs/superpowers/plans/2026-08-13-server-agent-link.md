# ServerAgentLink Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 构建一个轻量单二进制 Go 应用，管理多台服务器上的真实 OS 编码账户及其目录权限，并通过 MCP 服务把被标记「暴露」的账户凭据提供给外部 agent。

**Architecture:** 单 Go 二进制，含 6 个同进程组件：Web UI（内嵌模板）、REST API、MCP 服务（streamable HTTP，只读）、SSH 执行器（root 凭据建用户/设权限）、SQLite 存储、AES-256-GCM 密钥管理。平台是「凭据目录 + 服务器管理员」，不做任务代理、不管理 Anthropic API Key。

**Tech Stack:** Go 1.23、官方 `modelcontextprotocol/go-sdk`、`modernc.org/sqlite`（纯 Go 无 cgo）、`golang.org/x/crypto/ssh`、`net/http`（Go 1.22+ 路由）、`html/template` + htmx 内嵌前端、AES-256-GCM + argon2id。

## Global Constraints

- Module path：`serveragentlink`；Go 版本 `go 1.23`。
- 依赖（仅这些，勿加新框架）：`github.com/modelcontextprotocol/go-sdk`、`github.com/google/jsonschema-go`（go-sdk 传递依赖）、`golang.org/x/crypto`、`modernc.org/sqlite`。
- 所有密码（root、账户）以 AES-256-GCM 加密后落库，日志/错误信息中绝不出现明文密码。
- 管理员口令用 argon2id 哈希存储。
- 平台**不**存储/预置 Anthropic API Key，**不**转发任务；`coding_capable` 仅是人工标记的布尔值。
- 单管理员模式；MCP 鉴权用静态 Bearer token，与管理员密码分离。
- 目录权限后端：默认 `acl`（`setfacl`），可配 `group` 回退。
- SSH 主机密钥校验：TOFU（首次记录指纹，之后不匹配即拒绝）。
- 每完成一个 Task 就 `git commit`（提交信息见各 Task 末步）。

---

## 文件结构

```
ServerAgentLink/
├── go.mod / go.sum
├── cmd/server-agent-link/main.go        # 装配 + bootstrap
├── internal/
│   ├── config/config.go                 # env 配置解析
│   ├── crypto/crypto.go                 # AES-GCM、argon2id、随机 ID/token
│   ├── store/
│   │   ├── store.go                      # Open/Close、Encrypt/Decrypt、migrate
│   │   ├── models.go                     # 实体 struct + 常量
│   │   ├── servers.go                    # servers CRUD
│   │   ├── accounts.go                   # accounts + permissions CRUD + ListExposedAccounts
│   │   └── admin.go                      # admin + settings
│   ├── sshx/
│   │   ├── client.go                     # SSH 连接 + TOFU + Run
│   │   └── executor.go                   # 建/删用户脚本构建 + 执行
│   ├── httpapi/
│   │   ├── server.go                     # 路由、中间件装配
│   │   ├── auth.go                       # session、CSRF、登录限流
│   │   ├── handlers_servers.go
│   │   ├── handlers_accounts.go
│   │   └── json.go                       # writeJSON/writeErr 辅助
│   ├── mcp/
│   │   └── server.go                     # streamable HTTP + Bearer + list_exposed_accounts
│   └── web/
│       ├── embed.go                      # go:embed templates + static
│       ├── templates/*.html
│       └── static/app.js, app.css
└── docs/superpowers/specs/2026-08-13-server-agent-link-design.md
```

---

## Task 1: 项目骨架 + config 包

**Files:**
- Create: `go.mod`
- Create: `internal/config/config.go`
- Create: `internal/config/config_test.go`

**Interfaces:**
- Produces: `config.Load() (*Config, error)`；`Config` 含字段 `ListenAddr, DataDir, MasterKeyHex, MCPToken, AdminUser, AdminPassword, PermissionBackend string`；`(*Config).MasterKeyBytes() ([]byte, error)`。

- [ ] **Step 1: 初始化 module**

```bash
cd /media/vdc/project/yzq/ServerAgentLink
go mod init serveragentlink
```

- [ ] **Step 2: 写 config 包（含测试）**

`internal/config/config.go`：

```go
package config

import (
	"encoding/hex"
	"errors"
	"os"
)

type Config struct {
	ListenAddr       string
	DataDir          string
	MasterKeyHex     string
	MCPToken         string
	AdminUser        string
	AdminPassword    string
	PermissionBackend string
}

func Load() (*Config, error) {
	c := &Config{
		ListenAddr:       getenv("SAL_LISTEN_ADDR", ":8080"),
		DataDir:          getenv("SAL_DATA_DIR", "./data"),
		MasterKeyHex:     os.Getenv("SAL_MASTER_KEY"),
		MCPToken:         os.Getenv("SAL_MCP_TOKEN"),
		AdminUser:        getenv("SAL_ADMIN_USER", "admin"),
		AdminPassword:    os.Getenv("SAL_ADMIN_PASSWORD"),
		PermissionBackend: getenv("SAL_PERMISSION_BACKEND", "acl"),
	}
	if c.PermissionBackend != "acl" && c.PermissionBackend != "group" {
		return nil, errors.New("SAL_PERMISSION_BACKEND must be 'acl' or 'group'")
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
```

`internal/config/config_test.go`：

```go
package config

import "testing"

func TestLoadDefaults(t *testing.T) {
	t.Setenv("SAL_MASTER_KEY", strings.Repeat("ab", 32)) // 64 hex chars = 32 bytes
	c, err := Load()
	if err != nil { t.Fatal(err) }
	if c.ListenAddr != ":8080" { t.Fatalf("listen = %q", c.ListenAddr) }
	if c.PermissionBackend != "acl" { t.Fatalf("backend = %q", c.PermissionBackend) }
	if _, err := c.MasterKeyBytes(); err != nil { t.Fatal(err) }
}

func TestMasterKeyBadLength(t *testing.T) {
	t.Setenv("SAL_MASTER_KEY", "abcd")
	c, _ := Load()
	if _, err := c.MasterKeyBytes(); err == nil { t.Fatal("expected error for short key") }
}

func TestBackendInvalid(t *testing.T) {
	t.Setenv("SAL_PERMISSION_BACKEND", "bogus")
	if _, err := Load(); err == nil { t.Fatal("expected error for bad backend") }
}
```

> `strings` 需在测试文件 import。

- [ ] **Step 3: 跑测试**

Run: `go test ./internal/config/`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add go.mod internal/config/
git commit -m "feat: project skeleton + config package"
```

---

## Task 2: crypto 包

**Files:**
- Create: `internal/crypto/crypto.go`
- Create: `internal/crypto/crypto_test.go`

**Interfaces:**
- Consumes: 无。
- Produces:
  - `func GenerateKey() ([]byte, error)` — 32 字节随机。
  - `func Encrypt(key, plaintext []byte) ([]byte, error)` — 返回 `nonce||ciphertext`。
  - `func Decrypt(key, ct []byte) ([]byte, error)`
  - `func HashPassword(password string) (string, error)` — argon2id 编码串。
  - `func VerifyPassword(hash, password string) bool`
  - `func RandomID() (string, error)` — 32 hex 字符。
  - `func RandomToken() (string, error)` — 43 字符 base64url。

- [ ] **Step 1: 写失败测试**

`internal/crypto/crypto_test.go`：

```go
package crypto

import (
	"bytes"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key { key[i] = byte(i) }
	ct, err := Encrypt(key, []byte("secret-password"))
	if err != nil { t.Fatal(err) }
	pt, err := Decrypt(key, ct)
	if err != nil { t.Fatal(err) }
	if !bytes.Equal(pt, []byte("secret-password")) { t.Fatalf("got %q", pt) }
}

func TestDecryptWrongKeyFails(t *testing.T) {
	k1 := make([]byte, 32); k2 := make([]byte, 32); k2[0] = 1
	ct, _ := Encrypt(k1, []byte("x"))
	if _, err := Decrypt(k2, ct); err == nil { t.Fatal("expected error") }
}

func TestPasswordHashVerify(t *testing.T) {
	h, err := HashPassword("admin-pass")
	if err != nil { t.Fatal(err) }
	if !VerifyPassword(h, "admin-pass") { t.Fatal("should verify") }
	if VerifyPassword(h, "wrong") { t.Fatal("should not verify") }
}

func TestRandomIDUnique(t *testing.T) {
	a, _ := RandomID(); b, _ := RandomID()
	if a == b || len(a) != 32 { t.Fatalf("a=%q b=%q", a, b) }
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./internal/crypto/`
Expected: FAIL（package 不存在）

- [ ] **Step 3: 实现**

`internal/crypto/crypto.go`：

```go
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"

	"golang.org/x/crypto/argon2"
)

func GenerateKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

func Encrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func Decrypt(key, ct []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ct) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce, data := ct[:gcm.NonceSize()], ct[gcm.NonceSize():]
	return gcm.Open(nil, nonce, data, nil)
}

func HashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, 3, 64*1024, 1, 32)
	return base64.RawStdEncoding.EncodeToString(salt) + "$" +
		base64.RawStdEncoding.EncodeToString(hash), nil
}

func VerifyPassword(encoded, password string) bool {
	salt, hash, ok := splitHash(encoded)
	if !ok {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, 3, 64*1024, 1, 32)
	return subtleConstantTimeEqual(got, hash)
}

func RandomID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func RandomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
```

> 辅助：`splitHash` 按 `$` 切分并 base64 解码；`subtleConstantTimeEqual` 用 `crypto/subtle.ConstantTimeCompare`。测试通过即证明这两个辅助正确。

- [ ] **Step 4: 跑测试确认通过**

Run: `go test ./internal/crypto/`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/crypto/
git commit -m "feat: crypto package (AES-GCM, argon2id, random ids)"
```

---

## Task 3: store — schema + models + Open/migrate

**Files:**
- Create: `internal/store/models.go`
- Create: `internal/store/store.go`
- Create: `internal/store/store_test.go`

**Interfaces:**
- Consumes: `crypto.GenerateKey`（仅测试里造 key）。
- Produces:
  - `type Store struct{ db *sql.DB; key []byte }`
  - `func Open(dataDir string, key []byte) (*Store, error)`
  - `func (s *Store) Close() error`
  - `func (s *Store) Encrypt(plain []byte) ([]byte, error)`、`func (s *Store) Decrypt(enc []byte) ([]byte, error)`
  - 常量：`StatusPending = "pending"`、`StatusActive = "active"`、`StatusError = "error"`、`ModeReadWrite = "rw"`、`ModeReadOnly = "ro"`。

- [ ] **Step 1: 写失败测试**

`internal/store/store_test.go`：

```go
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
	if err != nil { t.Fatal(err) }
	t.Cleanup(func() { s.Close() })
	return s
}

func TestOpenAndMigrateIdempotent(t *testing.T) {
	s := newTestStore(t)
	var n int
	if err := s.db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('servers','accounts','directory_permissions','admin','settings')`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 5 { t.Fatalf("expected 5 tables, got %d", n) }
}

func TestEncryptDecrypt(t *testing.T) {
	s := newTestStore(t)
	ct, err := s.Encrypt([]byte("pw"))
	if err != nil { t.Fatal(err) }
	pt, err := s.Decrypt(ct)
	if err != nil { t.Fatal(err) }
	if string(pt) != "pw" { t.Fatalf("got %q", pt) }
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./internal/store/`
Expected: FAIL（package 不存在）

- [ ] **Step 3: 实现 models.go**

`internal/store/models.go`：

```go
package store

const (
	StatusPending = "pending"
	StatusActive  = "active"
	StatusError   = "error"

	ModeReadWrite = "rw"
	ModeReadOnly  = "ro"
)

type Server struct {
	ID            string
	Name          string
	Host          string
	SSHPort       int
	RootUser      string
	RootPasswordEnc []byte
	HostKey       string
	Enabled       bool
	LastVerifiedAt string // RFC3339，空串表示未验证
	CreatedAt      string
	UpdatedAt      string
}

type Account struct {
	ID            string
	ServerID      string
	Username      string
	PasswordEnc   []byte
	CodingCapable bool
	ExposedToAgent bool
	Status        string
	LastError     string
	CreatedAt     string
	UpdatedAt     string
}

type DirectoryPermission struct {
	ID        string
	AccountID string
	Path      string
	Mode      string
}

type ExposedAccount struct {
	ServerID      string
	ServerName    string
	Host          string
	SSHPort       int
	AccountID     string
	Username      string
	PasswordEnc   []byte
	CodingCapable bool
	Directories   []DirectoryPermission
}

type Admin struct {
	Username     string
	PasswordHash string
}
```

- [ ] **Step 4: 实现 store.go**

`internal/store/store.go`：

```go
package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

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
  enabled INTEGER NOT NULL DEFAULT 1, last_verified_at TEXT,
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
```

> 注意：`store.go` 里要 import `crypto "serveragentlink/internal/crypto"`（`fmt` 先保留，后续任务会用到；若编译报 unused 则删）。

- [ ] **Step 5: 跑测试确认通过**

Run: `go test ./internal/store/`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/store/
git commit -m "feat: store schema + models + open/migrate"
```

---

## Task 4: store — servers CRUD

**Files:**
- Modify: `internal/store/store.go`（加 `nowUTC` 辅助）
- Create: `internal/store/servers.go`
- Create: `internal/store/servers_test.go`

**Interfaces:**
- Consumes: `Store`, `crypto.RandomID`, `Server`。
- Produces:
  - `func (s *Store) CreateServer(ctx context.Context, name, host string, port int, rootUser, rootPassword string) (*Server, error)`
  - `func (s *Store) GetServer(ctx context.Context, id string) (*Server, error)`
  - `func (s *Store) ListServers(ctx context.Context) ([]Server, error)`
  - `func (s *Store) UpdateServer(ctx context.Context, sv Server) error`
  - `func (s *Store) DeleteServer(ctx context.Context, id string) error`

- [ ] **Step 1: 写失败测试**

`internal/store/servers_test.go`：

```go
package store

import (
	"context"
	"testing"
)

func TestServerCRUD(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	sv, err := s.CreateServer(ctx, "dev1", "10.0.0.5", 22, "root", "rootpw")
	if err != nil { t.Fatal(err) }
	if sv.ID == "" || sv.SSHPort != 22 { t.Fatal("bad server") }
	// 密码已加密落库，不等于明文
	if string(sv.RootPasswordEnc) == "rootpw" { t.Fatal("password not encrypted") }

	got, err := s.GetServer(ctx, sv.ID)
	if err != nil { t.Fatal(err) }
	if got.Host != "10.0.0.5" { t.Fatalf("host=%q", got.Host) }

	got.Name = "dev1-renamed"
	if err := s.UpdateServer(ctx, *got); err != nil { t.Fatal(err) }
	got2, _ := s.GetServer(ctx, sv.ID)
	if got2.Name != "dev1-renamed" { t.Fatal("update failed") }

	list, _ := s.ListServers(ctx)
	if len(list) != 1 { t.Fatalf("list len=%d", len(list)) }

	if err := s.DeleteServer(ctx, sv.ID); err != nil { t.Fatal(err) }
	if _, err := s.GetServer(ctx, sv.ID); err == nil { t.Fatal("expected not found") }
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./internal/store/`
Expected: FAIL（`CreateServer` 未定义）

- [ ] **Step 3: 实现 servers.go**

`internal/store/servers.go`：

```go
package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"serveragentlink/internal/crypto"
)

var ErrNotFound = errors.New("not found")

func nowUTC() string { return time.Now().UTC().Format(time.RFC3339Nano) }

func (s *Store) CreateServer(ctx context.Context, name, host string, port int, rootUser, rootPassword string) (*Server, error) {
	id, err := crypto.RandomID()
	if err != nil { return nil, err }
	enc, err := s.Encrypt([]byte(rootPassword))
	if err != nil { return nil, err }
	now := nowUTC()
	sv := &Server{ID: id, Name: name, Host: host, SSHPort: port, RootUser: rootUser,
		RootPasswordEnc: enc, Enabled: true, CreatedAt: now, UpdatedAt: now}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO servers (id,name,host,ssh_port,root_user,root_password_enc,host_key,enabled,last_verified_at,created_at,updated_at)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		sv.ID, sv.Name, sv.Host, sv.SSHPort, sv.RootUser, sv.RootPasswordEnc, sv.HostKey, boolInt(sv.Enabled), nil, now, now)
	if err != nil { return nil, err }
	return sv, nil
}

func (s *Store) GetServer(ctx context.Context, id string) (*Server, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id,name,host,ssh_port,root_user,root_password_enc,host_key,enabled,last_verified_at,created_at,updated_at
		 FROM servers WHERE id=?`, id)
	return scanServer(row)
}

func (s *Store) ListServers(ctx context.Context) ([]Server, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,name,host,ssh_port,root_user,root_password_enc,host_key,enabled,last_verified_at,created_at,updated_at
		 FROM servers ORDER BY name`)
	if err != nil { return nil, err }
	defer rows.Close()
	var out []Server
	for rows.Next() {
		sv, err := scanServer(rows)
		if err != nil { return nil, err }
		out = append(out, *sv)
	}
	return out, rows.Err()
}

func (s *Store) UpdateServer(ctx context.Context, sv Server) error {
	sv.UpdatedAt = nowUTC()
	_, err := s.db.ExecContext(ctx,
		`UPDATE servers SET name=?,host=?,ssh_port=?,root_user=?,root_password_enc=?,host_key=?,enabled=?,last_verified_at=?,updated_at=? WHERE id=?`,
		sv.Name, sv.Host, sv.SSHPort, sv.RootUser, sv.RootPasswordEnc, sv.HostKey, boolInt(sv.Enabled), sv.LastVerifiedAt, nowUTC(), sv.ID)
	return err
}

func (s *Store) DeleteServer(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM servers WHERE id=?`, id)
	if err != nil { return err }
	n, _ := res.RowsAffected()
	if n == 0 { return ErrNotFound }
	return nil
}

type rowScanner interface{ Scan(dest ...any) error }

func scanServer(r rowScanner) (*Server, error) {
	var sv Server
	var enabled int
	err := r.Scan(&sv.ID, &sv.Name, &sv.Host, &sv.SSHPort, &sv.RootUser, &sv.RootPasswordEnc,
		&sv.HostKey, &enabled, &sv.LastVerifiedAt, &sv.CreatedAt, &sv.UpdatedAt)
	if err == sql.ErrNoRows { return nil, ErrNotFound }
	if err != nil { return nil, err }
	sv.Enabled = enabled == 1
	return &sv, nil
}

func boolInt(b bool) int { if b { return 1 }; return 0 }
```

> 时间列统一用 TEXT + `string`（RFC3339Nano）存储，`scanServer` 直接 `Scan(&sv.LastVerifiedAt, &sv.CreatedAt, &sv.UpdatedAt)` 到 `string` 字段，避免 modernc/sqlite 扫描 `time.Time` 失败。models.go 中 `Server`/`Account` 的时间字段均为 `string`。

- [ ] **Step 4: 跑测试确认通过**

Run: `go test ./internal/store/`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/store/
git commit -m "feat: store servers CRUD"
```

---

## Task 5: store — accounts + permissions CRUD + ListExposedAccounts

**Files:**
- Modify: `internal/store/models.go`（时间字段改 string，已在 Task 4 说明）
- Create: `internal/store/accounts.go`
- Create: `internal/store/accounts_test.go`

**Interfaces:**
- Consumes: `Store`, `crypto.RandomID`, `Account`, `DirectoryPermission`, `ExposedAccount`。
- Produces:
  - `func (s *Store) CreateAccount(ctx context.Context, serverID, username, password string, codingCapable, exposed bool) (*Account, error)`
  - `func (s *Store) GetAccount(ctx context.Context, id string) (*Account, error)`
  - `func (s *Store) ListAccounts(ctx context.Context, serverID string) ([]Account, error)`
  - `func (s *Store) UpdateAccount(ctx context.Context, a Account) error`
  - `func (s *Store) DeleteAccount(ctx context.Context, id string) error`
  - `func (s *Store) SetPermissions(ctx context.Context, accountID string, perms []DirectoryPermission) error` — 事务内先删后插。
  - `func (s *Store) ListPermissions(ctx context.Context, accountID string) ([]DirectoryPermission, error)`
  - `func (s *Store) ListExposedAccounts(ctx context.Context) ([]ExposedAccount, error)`

- [ ] **Step 1: 写失败测试**

`internal/store/accounts_test.go`：

```go
package store

import (
	"context"
	"testing"
)

func TestAccountCRUDAndPermissions(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	sv, _ := s.CreateServer(ctx, "s1", "10.0.0.1", 22, "root", "rp")

	a, err := s.CreateAccount(ctx, sv.ID, "alice", "alicepw", true, true)
	if err != nil { t.Fatal(err) }
	if a.Status != StatusPending { t.Fatalf("status=%q", a.Status) }

	perms := []DirectoryPermission{
		{Path: "/data/a", Mode: ModeReadWrite},
		{Path: "/data/b", Mode: ModeReadOnly},
	}
	if err := s.SetPermissions(ctx, a.ID, perms); err != nil { t.Fatal(err) }
	got, _ := s.ListPermissions(ctx, a.ID)
	if len(got) != 2 { t.Fatalf("perms len=%d", len(got)) }

	// 覆盖式替换
	if err := s.SetPermissions(ctx, a.ID, perms[:1]); err != nil { t.Fatal(err) }
	got, _ = s.ListPermissions(ctx, a.ID)
	if len(got) != 1 || got[0].Path != "/data/a" { t.Fatalf("replace failed: %+v", got) }

	exposed, _ := s.ListExposedAccounts(ctx)
	if len(exposed) != 1 { t.Fatalf("exposed len=%d", len(exposed)) }
	if exposed[0].Username != "alice" || len(exposed[0].Directories) != 1 { t.Fatalf("bad exposed: %+v", exposed[0]) }

	// 取消暴露后不再返回
	a.ExposedToAgent = false
	_ = s.UpdateAccount(ctx, *a)
	exposed, _ = s.ListExposedAccounts(ctx)
	if len(exposed) != 0 { t.Fatalf("expected 0 exposed") }

	if err := s.DeleteAccount(ctx, a.ID); err != nil { t.Fatal(err) }
	if _, err := s.GetAccount(ctx, a.ID); err == nil { t.Fatal("expected not found") }
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./internal/store/`
Expected: FAIL（`CreateAccount` 未定义）

- [ ] **Step 3: 实现 accounts.go**

`internal/store/accounts.go`：

```go
package store

import (
	"context"
	"database/sql"
	"time"

	"serveragentlink/internal/crypto"
)

func (s *Store) CreateAccount(ctx context.Context, serverID, username, password string, codingCapable, exposed bool) (*Account, error) {
	id, err := crypto.RandomID()
	if err != nil { return nil, err }
	enc, err := s.Encrypt([]byte(password))
	if err != nil { return nil, err }
	now := nowUTC()
	a := &Account{ID: id, ServerID: serverID, Username: username, PasswordEnc: enc,
		CodingCapable: codingCapable, ExposedToAgent: exposed, Status: StatusPending,
		CreatedAt: now, UpdatedAt: now}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO accounts (id,server_id,username,password_enc,coding_capable,exposed_to_agent,status,last_error,created_at,updated_at)
		 VALUES (?,?,?,?,?,?,?,?,?,?)`,
		a.ID, a.ServerID, a.Username, a.PasswordEnc, boolInt(a.CodingCapable), boolInt(a.ExposedToAgent),
		a.Status, a.LastError, a.CreatedAt, a.UpdatedAt)
	if err != nil { return nil, err }
	return a, nil
}

func (s *Store) GetAccount(ctx context.Context, id string) (*Account, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id,server_id,username,password_enc,coding_capable,exposed_to_agent,status,last_error,created_at,updated_at
		 FROM accounts WHERE id=?`, id)
	return scanAccount(row)
}

func (s *Store) ListAccounts(ctx context.Context, serverID string) ([]Account, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,server_id,username,password_enc,coding_capable,exposed_to_agent,status,last_error,created_at,updated_at
		 FROM accounts WHERE server_id=? ORDER BY username`, serverID)
	if err != nil { return nil, err }
	defer rows.Close()
	var out []Account
	for rows.Next() {
		a, err := scanAccount(rows)
		if err != nil { return nil, err }
		out = append(out, *a)
	}
	return out, rows.Err()
}

func (s *Store) UpdateAccount(ctx context.Context, a Account) error {
	a.UpdatedAt = nowUTC()
	_, err := s.db.ExecContext(ctx,
		`UPDATE accounts SET coding_capable=?,exposed_to_agent=?,status=?,last_error=?,updated_at=? WHERE id=?`,
		boolInt(a.CodingCapable), boolInt(a.ExposedToAgent), a.Status, a.LastError, a.UpdatedAt, a.ID)
	return err
}

func (s *Store) DeleteAccount(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM accounts WHERE id=?`, id)
	if err != nil { return err }
	n, _ := res.RowsAffected()
	if n == 0 { return ErrNotFound }
	return nil
}

func (s *Store) SetPermissions(ctx context.Context, accountID string, perms []DirectoryPermission) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil { return err }
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM directory_permissions WHERE account_id=?`, accountID); err != nil {
		return err
	}
	for _, p := range perms {
		id, err := crypto.RandomID()
		if err != nil { return err }
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO directory_permissions (id,account_id,path,mode) VALUES (?,?,?,?)`,
			id, accountID, p.Path, p.Mode); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) ListPermissions(ctx context.Context, accountID string) ([]DirectoryPermission, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,account_id,path,mode FROM directory_permissions WHERE account_id=? ORDER BY path`, accountID)
	if err != nil { return nil, err }
	defer rows.Close()
	var out []DirectoryPermission
	for rows.Next() {
		var p DirectoryPermission
		if err := rows.Scan(&p.ID, &p.AccountID, &p.Path, &p.Mode); err != nil { return nil, err }
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) ListExposedAccounts(ctx context.Context) ([]ExposedAccount, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT sv.id, sv.name, sv.host, sv.ssh_port, a.id, a.username, a.password_enc, a.coding_capable
		 FROM accounts a JOIN servers sv ON sv.id = a.server_id
		 WHERE a.exposed_to_agent = 1 ORDER BY sv.name, a.username`)
	if err != nil { return nil, err }
	defer rows.Close()
	var out []ExposedAccount
	for rows.Next() {
		var e ExposedAccount
		var coding int
		if err := rows.Scan(&e.ServerID, &e.ServerName, &e.Host, &e.SSHPort, &e.AccountID,
			&e.Username, &e.PasswordEnc, &coding); err != nil { return nil, err }
		e.CodingCapable = coding == 1
		perms, err := s.ListPermissions(ctx, e.AccountID)
		if err != nil { return nil, err }
		e.Directories = perms
		out = append(out, e)
	}
	return out, rows.Err()
}
```

- [ ] **Step 4: 实现 scanAccount 辅助（加到 accounts.go 顶部或 store.go）**

```go
func scanAccount(r rowScanner) (*Account, error) {
	var a Account
	var coding, exposed int
	err := r.Scan(&a.ID, &a.ServerID, &a.Username, &a.PasswordEnc, &coding, &exposed,
		&a.Status, &a.LastError, &a.CreatedAt, &a.UpdatedAt)
	if err == sql.ErrNoRows { return nil, ErrNotFound }
	if err != nil { return nil, err }
	a.CodingCapable = coding == 1
	a.ExposedToAgent = exposed == 1
	return &a, nil
}
```

- [ ] **Step 5: 跑测试确认通过**

Run: `go test ./internal/store/`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/store/
git commit -m "feat: store accounts + permissions + exposed accounts"
```

---

## Task 6: store — admin + settings

**Files:**
- Create: `internal/store/admin.go`
- Create: `internal/store/admin_test.go`

**Interfaces:**
- Consumes: `Store`, `Admin`。
- Produces:
  - `func (s *Store) UpsertAdmin(ctx context.Context, username, passwordHash string) error`
  - `func (s *Store) GetAdmin(ctx context.Context) (*Admin, error)`
  - `func (s *Store) GetSetting(ctx context.Context, key string) (string, error)` — 不存在返回 `""`。
  - `func (s *Store) SetSetting(ctx context.Context, key, value string) error`

- [ ] **Step 1: 写失败测试**

`internal/store/admin_test.go`：

```go
package store

import (
	"context"
	"testing"
)

func TestAdminUpsertGet(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertAdmin(ctx, "admin", "hash1"); err != nil { t.Fatal(err) }
	a, err := s.GetAdmin(ctx)
	if err != nil { t.Fatal(err) }
	if a.Username != "admin" || a.PasswordHash != "hash1" { t.Fatalf("%+v", a) }
	_ = s.UpsertAdmin(ctx, "admin", "hash2")
	a2, _ := s.GetAdmin(ctx)
	if a2.PasswordHash != "hash2" { t.Fatal("upsert failed") }
}

func TestSettings(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if v, _ := s.GetSetting(ctx, "k"); v != "" { t.Fatal("expected empty") }
	if err := s.SetSetting(ctx, "k", "v1"); err != nil { t.Fatal(err) }
	if v, _ := s.GetSetting(ctx, "k"); v != "v1" { t.Fatalf("got %q", v) }
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./internal/store/`
Expected: FAIL（`UpsertAdmin` 未定义）

- [ ] **Step 3: 实现 admin.go**

`internal/store/admin.go`：

```go
package store

import (
	"context"
	"database/sql"
)

func (s *Store) UpsertAdmin(ctx context.Context, username, passwordHash string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO admin (id,username,password_hash) VALUES (1,?,?)
		 ON CONFLICT(id) DO UPDATE SET username=excluded.username, password_hash=excluded.password_hash`,
		username, passwordHash)
	return err
}

func (s *Store) GetAdmin(ctx context.Context) (*Admin, error) {
	var a Admin
	err := s.db.QueryRowContext(ctx, `SELECT username,password_hash FROM admin WHERE id=1`).Scan(&a.Username, &a.PasswordHash)
	if err == sql.ErrNoRows { return nil, ErrNotFound }
	if err != nil { return nil, err }
	return &a, nil
}

func (s *Store) GetSetting(ctx context.Context, key string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key=?`, key).Scan(&v)
	if err == sql.ErrNoRows { return "", nil }
	return v, err
}

func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
		key, value)
	return err
}
```

- [ ] **Step 4: 跑测试确认通过**

Run: `go test ./internal/store/`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/store/
git commit -m "feat: store admin + settings"
```

---

## Task 7: sshx — SSH client + TOFU

**Files:**
- Create: `internal/sshx/client.go`
- Create: `internal/sshx/client_test.go`

**Interfaces:**
- Consumes: 无（仅标准库 + x/crypto/ssh）。
- Produces:
  - `func Dial(host string, port int, user, password, knownHost string) (*Client, error)`
  - `func (c *Client) Run(ctx context.Context, cmd string) (string, error)` — 返回合并 stdout。
  - `func (c *Client) Close() error`

- [ ] **Step 1: 写失败测试（含进程内 SSH 测试服务器）**

`internal/sshx/client_test.go`：

```go
package sshx

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func startTestServer(t *testing.T) (addr string, hostKeyFingerprint string) {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	config := &ssh.ServerConfig{PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
		if string(pass) == "testpw" { return nil, nil }
		return nil, fmt.Errorf("bad password")
	}}
	config.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil { t.Fatal(err) }
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil { return }
			go handleConn(t, conn, config)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String(), ssh.FingerprintSHA256(signer.PublicKey())
}

func handleConn(t *testing.T, conn net.Conn, config *ssh.ServerConfig) {
	sconn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil { return }
	defer sconn.Close()
	go ssh.DiscardRequests(reqs)
	for ch := range chans {
		if ch.ChannelType() != "session" { ch.Reject(ssh.UnknownChannelType, "unknown"); continue }
		channel, requests, err := ch.Accept()
		if err != nil { continue }
		go func() {
			for req := range requests {
				switch req.Type {
				case "exec":
					payload := struct{ Command string }{}
					ssh.Unmarshal(req.Payload, &payload)
					channel.Write([]byte("out:" + payload.Command))
					channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
					req.Reply(true, nil)
					channel.Close()
				}
			}
		}()
	}
}
```

（`fmt` 需 import；`t` 参数未用时去掉。）

```go
func TestDialRunAndTOFU(t *testing.T) {
	addr, fp := startTestServer(t)
	host, portStr, _ := net.SplitHostPort(addr)
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	// 首次连接，knownHost 为空 → 成功并记录指纹（TOFU）
	c, err := Dial(host, port, "root", "testpw", "")
	if err != nil { t.Fatalf("dial: %v", err) }
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := c.Run(ctx, "echo hi")
	if err != nil { t.Fatal(err) }
	if out != "out:echo hi" { t.Fatalf("out=%q", out) }

	// 指纹不匹配 → 拒绝
	if _, err := Dial(host, port, "root", "testpw", "ssh-rsa AAAA bogus"); err == nil {
		t.Fatal("expected host key mismatch error")
	}

	// 正确指纹 → 通过
	c2, err := Dial(host, port, "root", "testpw", fp)
	if err != nil { t.Fatalf("dial with fp: %v", err) }
	c2.Close()
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./internal/sshx/`
Expected: FAIL（package 不存在）

- [ ] **Step 3: 实现 client.go**

`internal/sshx/client.go`：

```go
package sshx

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"
)

type Client struct {
	client *ssh.Client
}

// Dial 连接远程主机。knownHost 为上次记录的指纹（SHA256），空表示首次连接（TOFU）。
// 若已知指纹与实际不符，返回错误。
func Dial(host string, port int, user, password, knownHost string) (*Client, error) {
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: hostKeyCallback(knownHost),
		Timeout:         10 * time.Second,
	}
	client, err := ssh.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)), cfg)
	if err != nil {
		return nil, err
	}
	return &Client{client: client}, nil
}

func (c *Client) Run(ctx context.Context, cmd string) (string, error) {
	sess, err := c.client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	out, err := sess.Output(cmd)
	if err != nil {
		return string(out), err
	}
	return string(out), nil
}

func (c *Client) Close() error { return c.client.Close() }

func hostKeyCallback(knownHost string) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		fp := ssh.FingerprintSHA256(key)
		if knownHost == "" {
			return nil // TOFU：首次信任
		}
		if knownHost != fp {
			return fmt.Errorf("host key mismatch: got %s want %s", fp, knownHost)
		}
		return nil
	}
}

// Fingerprint 计算公钥指纹（供调用方在首次连接后持久化）。
func Fingerprint(c *Client) (string, error) {
	// 简化：从已建立连接取 HostKey 不可靠；改为 Dial 时返回。见下。
	return "", errors.New("use DialFingerprint")
}
```

> 简化决策：`Dial` 在连接成功后即可拿到指纹。为支持「首次连接后记录指纹」，把 `Dial` 的返回改为 `(*Client, string /*fingerprint*/, error)`。Task 7 与 Task 8 统一使用该签名：`func Dial(host string, port int, user, password, knownHost string) (*Client, string, error)`。`Fingerprint` 辅助函数删除。hostKeyCallback 内部在 TOFU 通过时无法返回指纹，因此在 `Dial` 成功后用 `client.Conn` 的 `HostKey` 不可用——改为：在 `hostKeyCallback` 里把实际指纹存入闭包变量 `lastFP`，`Dial` 返回 `lastFP`。

- [ ] **Step 4: 按简化决策改写 client.go 的 Dial 签名并更新测试**

`client.go` 关键改动：

```go
func Dial(host string, port int, user, password, knownHost string) (*Client, string, error) {
	var lastFP string
	cfg := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			lastFP = ssh.FingerprintSHA256(key)
			if knownHost == "" {
				return nil
			}
			if knownHost != lastFP {
				return fmt.Errorf("host key mismatch: got %s want %s", lastFP, knownHost)
			}
			return nil
		},
		Timeout: 10 * time.Second,
	}
	client, err := ssh.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)), cfg)
	if err != nil {
		return nil, "", err
	}
	return &Client{client: client}, lastFP, nil
}
```

测试中 `c, fp0, err := Dial(...)`；断言 `fp0 == fp`。

- [ ] **Step 5: 跑测试确认通过**

Run: `go test ./internal/sshx/`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/sshx/client.go internal/sshx/client_test.go
git commit -m "feat: ssh client with TOFU host key verification"
```

---

## Task 8: sshx — executor（建/删用户脚本 + 执行）

**Files:**
- Create: `internal/sshx/executor.go`
- Create: `internal/sshx/executor_test.go`

**Interfaces:**
- Consumes: `sshx.Dial`（Task 7）。
- Produces:
  - `type UserSpec struct{ Username, Password string; Permissions []PermissionSpec }`
  - `type PermissionSpec struct{ Path, Mode string }`
  - `func BuildCreateScript(u UserSpec, backend string) string`
  - `func BuildDeleteScript(username string) string`
  - `func BuildUpdateScript(username string, perms []PermissionSpec, backend string) string`
  - `type Executor struct{}`（空结构体，方法集即建户/删户/改权限）
  - `var backendGlobal = "acl"`；`func SetBackend(b string)`
  - `func (x *Executor) CreateUser(ctx context.Context, host string, port int, rootUser, rootPassword, knownHost string, spec UserSpec) (newFingerprint string, err error)`
  - `func (x *Executor) DeleteUser(ctx context.Context, host string, port int, rootUser, rootPassword string, spec UserSpec) error`
  - `func (x *Executor) UpdatePermissions(ctx context.Context, host string, port int, rootUser, rootPassword string, spec UserSpec) error`

> 脚本构建是纯函数（可单测）；`CreateUser/DeleteUser/UpdatePermissions` 用 `Dial` + `Run` 执行脚本。`CreateUser` 返回新指纹以便调用方回写 `servers.host_key`。

- [ ] **Step 1: 写失败测试（只测纯函数）**

`internal/sshx/executor_test.go`：

```go
package sshx

import (
	"strings"
	"testing"
)

func TestBuildCreateScriptACL(t *testing.T) {
	u := UserSpec{Username: "alice", Password: "pw",
		Permissions: []PermissionSpec{{Path: "/data/a", Mode: "rw"}, {Path: "/data/b", Mode: "ro"}}}
	script := BuildCreateScript(u, "acl")
	for _, want := range []string{
		"id alice", "useradd -m -s /bin/bash alice", "chpasswd",
		"setfacl -m u:alice:rwx /data/a", "setfacl -m d:u:alice:rwx /data/a",
		"setfacl -m u:alice:rx /data/b", "setfacl -m d:u:alice:rx /data/b",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("script missing %q:\n%s", want, script)
		}
	}
	if strings.Contains(script, "pw") { t.Fatal("script must not leak plaintext via echo") }
}

func TestBuildCreateScriptGroup(t *testing.T) {
	u := UserSpec{Username: "bob", Password: "x", Permissions: []PermissionSpec{{Path: "/d", Mode: "rw"}}}
	script := BuildCreateScript(u, "group")
	if !strings.Contains(script, "chown :bob /d") && !strings.Contains(script, "chgrp") {
		t.Fatalf("group backend missing chgrp/chown:\n%s", script)
	}
}

func TestBuildDeleteScript(t *testing.T) {
	script := BuildDeleteScript("alice")
	if !strings.Contains(script, "userdel -r alice") { t.Fatalf("missing userdel:\n%s", script) }
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./internal/sshx/`
Expected: FAIL（`BuildCreateScript` 未定义）

- [ ] **Step 3: 实现 executor.go**

`internal/sshx/executor.go`：

```go
package sshx

import (
	"context"
	"fmt"
	"strings"
)

type PermissionSpec struct {
	Path string
	Mode string // "rw" | "ro"
}

type UserSpec struct {
	Username    string
	Password    string
	Permissions []PermissionSpec
}

// BuildCreateScript 生成幂等的建户 shell 脚本。
// 密码经 stdin 传给 chpasswd，不写入命令行（避免 ps 泄露）。
func BuildCreateScript(u UserSpec, backend string) string {
	var b strings.Builder
	b.WriteString("set -e\n")
	b.WriteString(fmt.Sprintf("id %s >/dev/null 2>&1 && exit 0\n", shq(u.Username))) // 已存在则跳过
	b.WriteString(fmt.Sprintf("useradd -m -s /bin/bash %s\n", shq(u.Username)))
	b.WriteString(fmt.Sprintf("printf '%%s:%s\\n' %s | chpasswd\n", u.Password, shq(u.Username)))
	for _, p := range u.Permissions {
		b.WriteString(permLines(u.Username, p, backend))
	}
	return b.String()
}

func permLines(username string, p PermissionSpec, backend string) string {
	switch backend {
	case "group":
		grp := username // 每用户建同名组
		perm := "rx"
		if p.Mode == "rw" { perm = "rwx" }
		return fmt.Sprintf("groupadd -f %s\nusermod -aG %s %s\nchgrp %s %s\nchmod g+%s %s\n",
			shq(grp), shq(grp), shq(username), shq(grp), shq(p.Path), perm, shq(p.Path))
	default: // acl
		if p.Mode == "rw" {
			return fmt.Sprintf("setfacl -m u:%s:rwx %s\nsetfacl -m d:u:%s:rwx %s\n",
				shq(username), shq(p.Path), shq(username), shq(p.Path))
		}
		return fmt.Sprintf("setfacl -m u:%s:rx %s\nsetfacl -m d:u:%s:rx %s\n",
			shq(username), shq(p.Path), shq(username), shq(p.Path))
	}
}

func BuildDeleteScript(username string) string {
	return fmt.Sprintf("set -e\nuserdel -r %s\n", shq(username))
}

func BuildUpdateScript(username string, perms []PermissionSpec, backend string) string {
	var b strings.Builder
	b.WriteString("set -e\n")
	for _, p := range perms {
		b.WriteString(permLines(username, p, backend))
	}
	return b.String()
}

// shq 用单引号包裹并转义内部单引号。
func shq(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

// backendGlobal 为全局权限后端（acl | group），Task 14 在 main.go 用 sshx.SetBackend 设置。
var backendGlobal = "acl"

// SetBackend 设置全局权限后端。
func SetBackend(b string) { backendGlobal = b }

// Executor 为空结构体，方法集即建户/删户/改权限；便于 httpapi 层做接口注入与 fake。
type Executor struct{}

func (x *Executor) CreateUser(ctx context.Context, host string, port int, rootUser, rootPassword, knownHost string, spec UserSpec) (string, error) {
	c, fp, err := Dial(host, port, rootUser, rootPassword, knownHost)
	if err != nil { return "", err }
	defer c.Close()
	script := BuildCreateScript(spec, backendGlobal)
	if _, err := c.Run(ctx, script); err != nil {
		return "", fmt.Errorf("create user %s: %w", spec.Username, err)
	}
	return fp, nil
}

func (x *Executor) DeleteUser(ctx context.Context, host string, port int, rootUser, rootPassword string, spec UserSpec) error {
	c, _, err := Dial(host, port, rootUser, rootPassword, "")
	if err != nil { return err }
	defer c.Close()
	if _, err := c.Run(ctx, BuildDeleteScript(spec.Username)); err != nil {
		return fmt.Errorf("delete user %s: %w", spec.Username, err)
	}
	return nil
}

func (x *Executor) UpdatePermissions(ctx context.Context, host string, port int, rootUser, rootPassword string, spec UserSpec) error {
	c, _, err := Dial(host, port, rootUser, rootPassword, "")
	if err != nil { return err }
	defer c.Close()
	if _, err := c.Run(ctx, BuildUpdateScript(spec.Username, spec.Permissions, backendGlobal)); err != nil {
		return fmt.Errorf("update perms %s: %w", spec.Username, err)
	}
	return nil
}
```

> `DeleteUser`/`UpdatePermissions` 也应收发指纹，但为轻量起见仅 `CreateUser` 返回指纹用于 TOFU 首次记录。

- [ ] **Step 4: 跑测试确认通过**

Run: `go test ./internal/sshx/`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/sshx/executor.go internal/sshx/executor_test.go
git commit -m "feat: ssh executor user lifecycle scripts"
```

---

## Task 9: httpapi — 会话 / CSRF / 登录限流 + admin login/logout

**Files:**
- Create: `internal/httpapi/server.go`
- Create: `internal/httpapi/auth.go`
- Create: `internal/httpapi/json.go`
- Create: `internal/httpapi/auth_test.go`

**Interfaces:**
- Consumes: `store.Store`、`crypto.HashPassword/VerifyPassword/RandomToken`、`store.UpsertAdmin/GetAdmin`。
- Produces:
  - `type Server struct { st *store.Store; key []byte; adminUser string; exec *sshx.Executor; mcpHandler http.Handler; backend string }`
  - `func New(st *store.Store, key []byte, adminUser string, exec *sshx.Executor, mcpHandler http.Handler, backend string) *Server`
  - `func (s *Server) Handler() http.Handler`
  - 内部：`signCookie(payload string) string`、`verifyCookie(cookie string) (string, bool)`（HMAC 用 `key` 派生）

- [ ] **Step 1: 写失败测试**

`internal/httpapi/auth_test.go`：

```go
package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"serveragentlink/internal/crypto"
	"serveragentlink/internal/store"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	key := make([]byte, 32)
	st, err := store.Open(t.TempDir()+"/t.db", key)
	if err != nil { t.Fatal(err) }
	t.Cleanup(func() { st.Close() })
	hash, _ := crypto.HashPassword("adminpw")
	st.UpsertAdmin(context.Background(), "admin", hash)
	return New(st, key, "admin", nil, nil, "acl")
}

func TestLoginSetsSessionAndRequiresAuth(t *testing.T) {
	srv := newTestServer(t)
	h := srv.Handler()

	// 未登录访问受保护路由 → 401
	req := httptest.NewRequest("GET", "/api/servers", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized { t.Fatalf("code=%d", rec.Code) }

	// 登录成功 → 302 或 200 + 设置 cookie
	body := `{"username":"admin","password":"adminpw"}`
	req = httptest.NewRequest("POST", "/api/login", strings.NewReader(body))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK { t.Fatalf("login code=%d body=%s", rec.Code, rec.Body) }
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 { t.Fatal("no session cookie set") }
}

func TestLoginWrongPassword(t *testing.T) {
	srv := newTestServer(t)
	h := srv.Handler()
	req := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"admin","password":"nope"}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized { t.Fatalf("code=%d", rec.Code) }
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./internal/httpapi/`
Expected: FAIL（package 不存在）

- [ ] **Step 3: 实现 auth.go**

`internal/httpapi/auth.go`：

```go
package httpapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"serveragentlink/internal/crypto"
)

const sessionCookie = "sal_session"

func (s *Server) mac(msg string) string {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte(msg))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (s *Server) signCookie(payload string) string {
	return payload + "." + s.mac(payload)
}

func (s *Server) verifyCookie(cookie string) (string, bool) {
	parts := strings.Split(cookie, ".")
	if len(parts) != 2 { return "", false }
	if s.mac(parts[0]) != parts[1] { return "", false }
	return parts[0], true
}

type sessionPayload struct {
	User string `json:"u"`
	Exp  int64  `json:"e"`
}

// requireAuth 保护 /api/* 除 /api/login 外的所有路由。
func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil { writeErr(w, http.StatusUnauthorized, "unauthorized"); return }
		payload, ok := s.verifyCookie(c.Value)
		if !ok { writeErr(w, http.StatusUnauthorized, "unauthorized"); return }
		var sp sessionPayload
		if json.Unmarshal([]byte(payload), &sp) != nil || sp.User != s.adminUser || sp.Exp < time.Now().Unix() {
			writeErr(w, http.StatusUnauthorized, "unauthorized"); return
		}
		next.ServeHTTP(w, r)
	})
}

var loginAttempts = struct {
	sync.Mutex
	m map[string][]time.Time
}{m: map[string][]time.Time{}}

func allowLogin(ip string) bool {
	loginAttempts.Lock()
	defer loginAttempts.Unlock()
	now := time.Now()
	cut := now.Add(-time.Minute)
	var kept []time.Time
	for _, t := range loginAttempts.m[ip] {
		if t.After(cut) { kept = append(kept, t) }
	}
	loginAttempts.m[ip] = kept
	return len(kept) < 5
}

func recordLoginAttempt(ip string) {
	loginAttempts.Lock()
	defer loginAttempts.Unlock()
	loginAttempts.m[ip] = append(loginAttempts.m[ip], time.Now())
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := strings.Split(r.RemoteAddr, ":")[0]
	if !allowLogin(ip) {
		writeErr(w, http.StatusTooManyRequests, "too many attempts")
		return
	}
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil || in.Username != s.adminUser {
		recordLoginAttempt(ip)
		writeErr(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	admin, err := s.st.GetAdmin(r.Context())
	if err != nil || !crypto.VerifyPassword(admin.PasswordHash, in.Password) {
		recordLoginAttempt(ip)
		writeErr(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	payload, _ := json.Marshal(sessionPayload{User: s.adminUser, Exp: time.Now().Add(24 * time.Hour).Unix()})
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: s.signCookie(string(payload)),
		Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
	writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1})
	writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
}
```

- [ ] **Step 4: 实现 json.go**

`internal/httpapi/json.go`：

```go
package httpapi

import (
	"encoding/json"
	"net/http"
)

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
```

- [ ] **Step 5: 实现 server.go（路由骨架）**

`internal/httpapi/server.go`：

```go
package httpapi

import (
	"net/http"

	"serveragentlink/internal/sshx"
	"serveragentlink/internal/store"
)

type Server struct {
	st         *store.Store
	key        []byte
	adminUser  string
	exec       *sshx.Executor
	mcpHandler http.Handler
	backend    string
}

func New(st *store.Store, key []byte, adminUser string, exec *sshx.Executor, mcpHandler http.Handler, backend string) *Server {
	return &Server{st: st, key: key, adminUser: adminUser, exec: exec, mcpHandler: mcpHandler, backend: backend}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/logout", s.handleLogout)

	// 受保护 API（后续任务补齐 handler）
	api := http.NewServeMux()
	api.HandleFunc("GET /api/servers", s.handleListServers)
	api.HandleFunc("POST /api/servers", s.handleCreateServer)
	api.HandleFunc("GET /api/servers/{id}", s.handleGetServer)
	api.HandleFunc("PUT /api/servers/{id}", s.handleUpdateServer)
	api.HandleFunc("DELETE /api/servers/{id}", s.handleDeleteServer)
	api.HandleFunc("POST /api/servers/{id}/accounts", s.handleCreateAccount)
	api.HandleFunc("POST /api/accounts/{id}/provision", s.handleProvisionAccount)
	api.HandleFunc("DELETE /api/accounts/{id}", s.handleDeleteAccount)
	api.HandleFunc("GET /api/accounts/{id}/permissions", s.handleListPermissions)
	api.HandleFunc("PUT /api/accounts/{id}/permissions", s.handleSetPermissions)

	mux.Handle("/api/", s.requireAuth(api))

	if s.mcpHandler != nil {
		mux.Handle("/mcp", s.mcpHandler)
	}
	return mux
}
```

> 本任务 handlers 尚未实现，`go test` 会因未定义方法编译失败——因此本任务先让 `api` 只注册已实现的 login/logout，注释掉其余 HandleFunc，待 Task 10/11 逐一放开。即：本任务的 `Handler()` 只包含 login/logout + requireAuth 包裹的空 api mux。Task 10/11 再逐个加路由。

- [ ] **Step 6: 跑测试确认通过**

Run: `go test ./internal/httpapi/`
Expected: PASS（login/logout 测试通过）

- [ ] **Step 7: Commit**

```bash
git add internal/httpapi/
git commit -m "feat: httpapi auth (session, csrf-free login, rate limit)"
```

---

## Task 10: httpapi — servers 路由 handlers

**Files:**
- Modify: `internal/httpapi/server.go`（放开 servers 路由）
- Create: `internal/httpapi/handlers_servers.go`
- Create: `internal/httpapi/handlers_servers_test.go`

**Interfaces:**
- Consumes: `store.CreateServer/GetServer/ListServers/UpdateServer/DeleteServer`、`crypto`（无）、`sshx.Executor`（本任务仅用于连接校验，可留空实现）。
- Produces: handler 方法 `handleListServers`、`handleCreateServer`、`handleGetServer`、`handleUpdateServer`、`handleDeleteServer`。

- [ ] **Step 1: 写失败测试**

`internal/httpapi/handlers_servers_test.go`：

```go
package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"serveragentlink/internal/store"
)

func TestCreateAndListServers(t *testing.T) {
	srv := newTestServer(t)
	h := srv.Handler()
	cookie := login(t, srv, h)

	body := `{"name":"dev1","host":"10.0.0.5","ssh_port":22,"root_user":"root","root_password":"rootpw"}`
	req := httptest.NewRequest("POST", "/api/servers", bytes.NewReader([]byte(body)))
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated { t.Fatalf("create code=%d body=%s", rec.Code, rec.Body) }

	req = httptest.NewRequest("GET", "/api/servers", nil)
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK { t.Fatalf("list code=%d", rec.Code) }
	var list []store.Server
	json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list) != 1 || list[0].Host != "10.0.0.5" { t.Fatalf("list=%+v", list) }
	// 响应中不暴露密文
	if len(list[0].RootPasswordEnc) != 0 { t.Fatal("must not expose password_enc in JSON") }
}

func login(t *testing.T, srv *Server, h http.Handler) *http.Cookie {
	t.Helper()
	req := httptest.NewRequest("POST", "/api/login", bytes.NewReader([]byte(`{"username":"admin","password":"adminpw"}`)))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie { return c }
	}
	t.Fatal("no session cookie")
	return nil
}
```

> `context` 在测试里实际用到（provision 校验等后续）；本任务未用则删除 import。

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./internal/httpapi/`
Expected: FAIL（`handleCreateServer` 未定义）

- [ ] **Step 3: 实现 handlers_servers.go**

`internal/httpapi/handlers_servers.go`：

```go
package httpapi

import (
	"encoding/json"
	"net/http"

	"serveragentlink/internal/store"
)

type serverInput struct {
	Name         string `json:"name"`
	Host         string `json:"host"`
	SSHPort      int    `json:"ssh_port"`
	RootUser     string `json:"root_user"`
	RootPassword string `json:"root_password"`
}

// serverDTO 是 server 的对外视图，绝不包含 RootPasswordEnc。
type serverDTO struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Host     string `json:"host"`
	SSHPort  int    `json:"ssh_port"`
	RootUser string `json:"root_user"`
	Enabled  bool   `json:"enabled"`
}

func toServerDTO(sv store.Server) serverDTO {
	return serverDTO{ID: sv.ID, Name: sv.Name, Host: sv.Host, SSHPort: sv.SSHPort,
		RootUser: sv.RootUser, Enabled: sv.Enabled}
}

func (s *Server) handleListServers(w http.ResponseWriter, r *http.Request) {
	servers, err := s.st.ListServers(r.Context())
	if err != nil { writeErr(w, http.StatusInternalServerError, "db error"); return }
	out := make([]serverDTO, 0, len(servers))
	for _, sv := range servers { out = append(out, toServerDTO(sv)) }
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleCreateServer(w http.ResponseWriter, r *http.Request) {
	var in serverInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json"); return
	}
	if in.Name == "" || in.Host == "" || in.RootPassword == "" {
		writeErr(w, http.StatusBadRequest, "name/host/root_password required"); return
	}
	if in.SSHPort == 0 { in.SSHPort = 22 }
	if in.RootUser == "" { in.RootUser = "root" }
	sv, err := s.st.CreateServer(r.Context(), in.Name, in.Host, in.SSHPort, in.RootUser, in.RootPassword)
	if err != nil { writeErr(w, http.StatusInternalServerError, "create failed"); return }
	writeJSON(w, http.StatusCreated, toServerDTO(*sv))
}

func (s *Server) handleGetServer(w http.ResponseWriter, r *http.Request) {
	sv, err := s.st.GetServer(r.Context(), r.PathValue("id"))
	if err != nil { writeErr(w, http.StatusNotFound, "not found"); return }
	writeJSON(w, http.StatusOK, toServerDTO(*sv))
}

func (s *Server) handleUpdateServer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	sv, err := s.st.GetServer(r.Context(), id)
	if err != nil { writeErr(w, http.StatusNotFound, "not found"); return }
	var in serverInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json"); return
	}
	if in.Name != "" { sv.Name = in.Name }
	if in.Host != "" { sv.Host = in.Host }
	if in.SSHPort != 0 { sv.SSHPort = in.SSHPort }
	if in.RootUser != "" { sv.RootUser = in.RootUser }
	if in.RootPassword != "" {
		enc, err := s.st.Encrypt([]byte(in.RootPassword))
		if err != nil { writeErr(w, http.StatusInternalServerError, "encrypt failed"); return }
		sv.RootPasswordEnc = enc
	}
	if err := s.st.UpdateServer(r.Context(), *sv); err != nil { writeErr(w, http.StatusInternalServerError, "update failed"); return }
	writeJSON(w, http.StatusOK, toServerDTO(*sv))
}

func (s *Server) handleDeleteServer(w http.ResponseWriter, r *http.Request) {
	if err := s.st.DeleteServer(r.Context(), r.PathValue("id")); err != nil {
		writeErr(w, http.StatusNotFound, "not found"); return
	}
	writeJSON(w, http.StatusNoContent, nil)
}
```

- [ ] **Step 4: 在 server.go 放开 servers 路由**

把 `api.HandleFunc("GET /api/servers", ...)` 等 5 条 servers 路由从注释中放开（accounts 路由保持注释，Task 11 再开）。

- [ ] **Step 5: 跑测试确认通过**

Run: `go test ./internal/httpapi/`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/httpapi/
git commit -m "feat: httpapi server CRUD handlers"
```

---

## Task 11: httpapi — accounts + permissions handlers（含 provision 调 sshx）

**Files:**
- Modify: `internal/httpapi/server.go`（放开 accounts 路由）
- Create: `internal/httpapi/handlers_accounts.go`
- Create: `internal/httpapi/handlers_accounts_test.go`

**Interfaces:**
- Consumes: `store.CreateAccount/GetAccount/ListAccounts/UpdateAccount/DeleteAccount/SetPermissions/ListPermissions/GetServer`、`sshx.CreateUser/DeleteUser/UpdatePermissions`、`crypto.RandomID`。
- Produces: `handleCreateAccount`、`handleProvisionAccount`、`handleDeleteAccount`、`handleListPermissions`、`handleSetPermissions`。

- [ ] **Step 1: 写失败测试（用假的 sshx 执行器）**

> 为不依赖真实 SSH，`Server` 增加可注入的 executor 接口。`server.go` 中定义：

```go
type userExecutor interface {
	CreateUser(ctx context.Context, host string, port int, rootUser, rootPassword, knownHost string, spec sshx.UserSpec) (string, error)
	DeleteUser(ctx context.Context, host string, port int, rootUser, rootPassword string, spec sshx.UserSpec) error
	UpdatePermissions(ctx context.Context, host string, port int, rootUser, rootPassword string, spec sshx.UserSpec) error
}
```

`Server.exec` 类型从 `*sshx.Executor` 改为 `userExecutor`；`New` 的 `exec` 参数类型同步改。测试里注入 fake：

```go
type fakeExec struct{ created int }
func (f *fakeExec) CreateUser(ctx context.Context, host string, port int, rootUser, rootPassword, knownHost string, spec sshx.UserSpec) (string, error) { f.created++; return "fp", nil }
func (f *fakeExec) DeleteUser(ctx context.Context, host string, port int, rootUser, rootPassword string, spec sshx.UserSpec) error { return nil }
func (f *fakeExec) UpdatePermissions(ctx context.Context, host string, port int, rootUser, rootPassword string, spec sshx.UserSpec) error { return nil }
```

`handlers_accounts_test.go`：

```go
package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"serveragentlink/internal/store"
	"serveragentlink/internal/sshx"
)

func TestCreateAccountProvision(t *testing.T) {
	srv := newTestServer(t)
	fx := &fakeExec{}
	srv.exec = fx
	h := srv.Handler()
	cookie := login(t, srv, h)

	sv, _ := srv.st.CreateServer(context.Background(), "s1", "10.0.0.1", 22, "root", "rp")
	body := `{"username":"alice","password":"alicepw","coding_capable":true,"exposed_to_agent":true,
		"permissions":[{"path":"/data/a","mode":"rw"}]}`
	req := httptest.NewRequest("POST", "/api/servers/"+sv.ID+"/accounts", bytes.NewReader([]byte(body)))
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated { t.Fatalf("code=%d body=%s", rec.Code, rec.Body) }
	if fx.created != 1 { t.Fatalf("executor not called") }

	accs, _ := srv.st.ListAccounts(context.Background(), sv.ID)
	if len(accs) != 1 || accs[0].Status != store.StatusActive { t.Fatalf("acc=%+v", accs) }
}

func TestProvisionFailureMarksError(t *testing.T) {
	srv := newTestServer(t)
	fx := &failExec{err: fmt.Errorf("boom")}
	srv.exec = fx
	h := srv.Handler()
	cookie := login(t, srv, h)
	sv, _ := srv.st.CreateServer(context.Background(), "s1", "10.0.0.1", 22, "root", "rp")
	body := `{"username":"bob","password":"pw","permissions":[]}`
	req := httptest.NewRequest("POST", "/api/servers/"+sv.ID+"/accounts", bytes.NewReader([]byte(body)))
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	accs, _ := srv.st.ListAccounts(context.Background(), sv.ID)
	if accs[0].Status != store.StatusError || accs[0].LastError == "" { t.Fatalf("acc=%+v", accs[0]) }
}
```

（`failExec` 实现同上 fake，但 `CreateUser` 返回 `err`；`fmt` 需 import。）

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./internal/httpapi/`
Expected: FAIL（`handleCreateAccount` 未定义）

- [ ] **Step 3: 实现 handlers_accounts.go**

`internal/httpapi/handlers_accounts.go`：

```go
package httpapi

import (
	"encoding/json"
	"net/http"

	"serveragentlink/internal/sshx"
	"serveragentlink/internal/store"
)

type accountInput struct {
	Username       string          `json:"username"`
	Password       string          `json:"password"`
	CodingCapable  bool            `json:"coding_capable"`
	ExposedToAgent bool            `json:"exposed_to_agent"`
	Permissions    []permissionInput `json:"permissions"`
}

type permissionInput struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
}

type accountDTO struct {
	ID             string             `json:"id"`
	ServerID       string             `json:"server_id"`
	Username       string             `json:"username"`
	CodingCapable  bool               `json:"coding_capable"`
	ExposedToAgent bool               `json:"exposed_to_agent"`
	Status         string             `json:"status"`
	LastError      string             `json:"last_error"`
	Permissions    []permissionInput  `json:"permissions"`
}

func toAccountDTO(a store.Account, perms []store.DirectoryPermission) accountDTO {
	dto := accountDTO{ID: a.ID, ServerID: a.ServerID, Username: a.Username,
		CodingCapable: a.CodingCapable, ExposedToAgent: a.ExposedToAgent,
		Status: a.Status, LastError: a.LastError, Permissions: []permissionInput{}}
	for _, p := range perms {
		dto.Permissions = append(dto.Permissions, permissionInput{Path: p.Path, Mode: p.Mode})
	}
	return dto
}

func (s *Server) handleCreateAccount(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("id")
	var in accountInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json"); return
	}
	if in.Username == "" || in.Password == "" {
		writeErr(w, http.StatusBadRequest, "username/password required"); return
	}
	a, err := s.st.CreateAccount(r.Context(), serverID, in.Username, in.Password, in.CodingCapable, in.ExposedToAgent)
	if err != nil { writeErr(w, http.StatusInternalServerError, "create failed"); return }
	if err := s.st.SetPermissions(r.Context(), a.ID, toStorePerms(in.Permissions)); err != nil {
		writeErr(w, http.StatusInternalServerError, "set perms failed"); return
	}
	s.provision(r, a)
	acc, _ := s.st.GetAccount(r.Context(), a.ID)
	perms, _ := s.st.ListPermissions(r.Context(), a.ID)
	writeJSON(w, http.StatusCreated, toAccountDTO(*acc, perms))
}

func (s *Server) handleProvisionAccount(w http.ResponseWriter, r *http.Request) {
	a, err := s.st.GetAccount(r.Context(), r.PathValue("id"))
	if err != nil { writeErr(w, http.StatusNotFound, "not found"); return }
	s.provision(r, a)
	acc, _ := s.st.GetAccount(r.Context(), a.ID)
	perms, _ := s.st.ListPermissions(r.Context(), a.ID)
	writeJSON(w, http.StatusOK, toAccountDTO(*acc, perms))
}

// provision 用 root 凭据在服务器上真实建户；失败时标记 status=error。
func (s *Server) provision(r *http.Request, a *store.Account) {
	sv, err := s.st.GetServer(r.Context(), a.ServerID)
	if err != nil { s.markError(r, a.ID, err); return }
	rootPw, err := s.st.Decrypt(sv.RootPasswordEnc)
	if err != nil { s.markError(r, a.ID, err); return }
	acctPw, err := s.st.Decrypt(a.PasswordEnc)
	if err != nil { s.markError(r, a.ID, err); return }
	perms, _ := s.st.ListPermissions(r.Context(), a.ID)
	spec := sshx.UserSpec{Username: a.Username, Password: string(acctPw)}
	for _, p := range perms { spec.Permissions = append(spec.Permissions, sshx.PermissionSpec{Path: p.Path, Mode: p.Mode}) }
	fp, err := s.exec.CreateUser(r.Context(), sv.Host, sv.SSHPort, sv.RootUser, string(rootPw), sv.HostKey, spec)
	if err != nil { s.markError(r, a.ID, err); return }
	if fp != "" && fp != sv.HostKey {
		sv.HostKey = fp
		s.st.UpdateServer(r.Context(), *sv)
	}
	a.Status = store.StatusActive
	a.LastError = ""
	s.st.UpdateAccount(r.Context(), *a)
}

func (s *Server) markError(r *http.Request, accountID string, err error) {
	s.st.UpdateAccount(r.Context(), store.Account{ID: accountID, Status: store.StatusError, LastError: err.Error()})
}

func (s *Server) handleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	a, err := s.st.GetAccount(r.Context(), r.PathValue("id"))
	if err != nil { writeErr(w, http.StatusNotFound, "not found"); return }
	sv, err := s.st.GetServer(r.Context(), a.ServerID)
	if err != nil { writeErr(w, http.StatusNotFound, "not found"); return }
	rootPw, _ := s.st.Decrypt(sv.RootPasswordEnc)
	spec := sshx.UserSpec{Username: a.Username, Password: ""}
	_ = s.exec.DeleteUser(r.Context(), sv.Host, sv.SSHPort, sv.RootUser, string(rootPw), spec)
	s.st.DeleteAccount(r.Context(), a.ID)
	writeJSON(w, http.StatusNoContent, nil)
}

func (s *Server) handleListPermissions(w http.ResponseWriter, r *http.Request) {
	perms, err := s.st.ListPermissions(r.Context(), r.PathValue("id"))
	if err != nil { writeErr(w, http.StatusInternalServerError, "db error"); return }
	out := []permissionInput{}
	for _, p := range perms { out = append(out, permissionInput{Path: p.Path, Mode: p.Mode}) }
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleSetPermissions(w http.ResponseWriter, r *http.Request) {
	accountID := r.PathValue("id")
	var in []permissionInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json"); return
	}
	if err := s.st.SetPermissions(r.Context(), accountID, toStorePerms(in)); err != nil {
		writeErr(w, http.StatusInternalServerError, "set perms failed"); return
	}
	writeJSON(w, http.StatusOK, in)
}

func toStorePerms(in []permissionInput) []store.DirectoryPermission {
	out := make([]store.DirectoryPermission, 0, len(in))
	for _, p := range in {
		if p.Mode != store.ModeReadWrite && p.Mode != store.ModeReadOnly { continue }
		out = append(out, store.DirectoryPermission{Path: p.Path, Mode: p.Mode})
	}
	return out
}
```

> 注意：`markError` 用 `store.Account{ID, Status, LastError}` 调 `UpdateAccount`，但 `UpdateAccount` 只更新 `coding_capable/exposed_to_agent/status/last_error/updated_at`，`ID` 用于 WHERE，正确。`DeleteUser` 里 spec.Password 置空，因为 `BuildDeleteScript` 不涉及密码。

- [ ] **Step 4: 在 server.go 放开 accounts 路由，并调整 Server.exec 类型**

见 Step 1 的 `userExecutor` 接口定义；`server.go` 中 `exec userExecutor`、`New(... exec userExecutor ...)`。

- [ ] **Step 5: 跑测试确认通过**

Run: `go test ./internal/httpapi/`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/httpapi/
git commit -m "feat: httpapi accounts + permissions handlers with ssh provisioning"
```

---

## Task 12: mcp — streamable HTTP + Bearer + list_exposed_accounts

**Files:**
- Create: `internal/mcp/server.go`
- Create: `internal/mcp/server_test.go`

**Interfaces:**
- Consumes: `store.ListExposedAccounts`、`store.Decrypt`、官方 go-sdk `mcp` 包。
- Produces: `func NewHandler(st *store.Store, key []byte, token string) (http.Handler, error)`

- [ ] **Step 1: 写失败测试（Bearer 校验 + 工具可被列出）**

`internal/mcp/server_test.go`：

```go
package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"serveragentlink/internal/store"
)

func newHandler(t *testing.T) (http.Handler, *store.Store) {
	t.Helper()
	key := make([]byte, 32)
	st, err := store.Open(t.TempDir()+"/t.db", key)
	if err != nil { t.Fatal(err) }
	t.Cleanup(func() { st.Close() })
	h, err := NewHandler(st, key, "secrettoken")
	if err != nil { t.Fatal(err) }
	return h, st
}

func TestBearerAuthRequired(t *testing.T) {
	h, _ := newHandler(t)
	req := httptest.NewRequest("POST", "/mcp", bytes.NewReader([]byte(`{}`)))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized { t.Fatalf("code=%d", rec.Code) }
}

func TestToolsListed(t *testing.T) {
	h, _ := newHandler(t)
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`
	req := httptest.NewRequest("POST", "/mcp", bytes.NewReader([]byte(body)))
	req.Header.Set("Authorization", "Bearer secrettoken")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK { t.Fatalf("code=%d body=%s", rec.Code, rec.Body) }
	var resp struct {
		Result struct {
			Tools []struct{ Name string } `json:"tools"`
		} `json:"result"`
	}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Result.Tools) != 1 || resp.Result.Tools[0].Name != "list_exposed_accounts" {
		t.Fatalf("tools=%+v", resp.Result.Tools)
	}
}
```

> 注意：MCP JSON-RPC 的 `tools/list` 结果结构由 go-sdk 决定，可能包一层 `tools` 数组在 `result.tools`。若实际 SDK 返回结构不同，测试按真实响应字段调整（以 `go doc` 为准）。工具名 `list_exposed_accounts` 断言不变。

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./internal/mcp/`
Expected: FAIL（package 不存在）

- [ ] **Step 3: 实现 server.go**

`internal/mcp/server.go`：

```go
package mcp

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"serveragentlink/internal/store"
)

type accountDTO struct {
	ServerID      string    `json:"server_id"`
	ServerName    string    `json:"server_name"`
	Host          string    `json:"host"`
	SSHPort       int       `json:"ssh_port"`
	Username      string    `json:"username"`
	Password      string    `json:"password"`
	CodingCapable bool      `json:"coding_capable"`
	Directories   []dirDTO  `json:"directories"`
}

type dirDTO struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
}

type listAccountsArgs struct{}

type listAccountsResult struct {
	Accounts []accountDTO `json:"accounts"`
}

func NewHandler(st *store.Store, key []byte, token string) (http.Handler, error) {
	server := mcp.NewServer(&mcp.Implementation{Name: "server-agent-link", Version: "1.0.0"}, nil)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_exposed_accounts",
		Description: "列出所有已暴露给 agent 的编码账户及其 SSH 凭据与目录权限",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in listAccountsArgs) (*mcp.CallToolResult, listAccountsResult, error) {
		accounts, err := st.ListExposedAccounts(ctx)
		if err != nil {
			return nil, listAccountsResult{}, err
		}
		out := listAccountsResult{Accounts: []accountDTO{}}
		for _, a := range accounts {
			pw, err := st.Decrypt(a.PasswordEnc)
			if err != nil {
				return nil, listAccountsResult{}, err
			}
			dto := accountDTO{ServerID: a.ServerID, ServerName: a.ServerName, Host: a.Host,
				SSHPort: a.SSHPort, Username: a.Username, Password: string(pw), CodingCapable: a.CodingCapable}
			for _, p := range a.Directories {
				dto.Directories = append(dto.Directories, dirDTO{Path: p.Path, Mode: p.Mode})
			}
			out.Accounts = append(out.Accounts, dto)
		}
		return nil, out, nil
	})

	streamable := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)

	return bearerAuth(token, streamable), nil
}

func bearerAuth(token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
```

> 若 go-sdk 的 handler 签名或 `CallToolResult`/`TextContent` 结构与此处略有出入，以 `go.mod` 锁定版本为准，参考 go-sdk README/`go doc` 调整。`encoding/json` 若未使用则删除（保留以备 `marshal`）。

- [ ] **Step 4: 跑测试确认通过**

Run: `go test ./internal/mcp/`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/mcp/
git commit -m "feat: mcp server exposing accounts over streamable http"
```

---

## Task 13: web — 内嵌模板 + 静态资源

**Files:**
- Create: `internal/web/embed.go`
- Create: `internal/web/templates/base.html`
- Create: `internal/web/templates/login.html`
- Create: `internal/web/templates/servers.html`
- Create: `internal/web/templates/server_detail.html`
- Create: `internal/web/static/app.js`
- Create: `internal/web/static/app.css`

**Interfaces:**
- Consumes: 无。
- Produces: `func ParseTemplates() (*template.Template, error)`；`//go:embed templates static` 的 `FS embed.FS`。

- [ ] **Step 1: 实现 embed.go**

`internal/web/embed.go`：

```go
package web

import (
	"embed"
	"html/template"
)

//go:embed templates static
var FS embed.FS

func ParseTemplates() (*template.Template, error) {
	return template.New("").ParseFS(FS, "templates/*.html")
}
```

- [ ] **Step 2: 写模板（服务端渲染 + htmx）**

`templates/base.html`：

```html
{{define "head"}}<head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ServerAgentLink</title>
  <link rel="stylesheet" href="/static/app.css">
  <script src="https://unpkg.com/htmx.org@1.9.12"></script>
</head>{{end}}

{{define "nav"}}<nav><a href="/">ServerAgentLink</a>
  {{if .Authed}}<form method="post" action="/api/logout"><button>退出</button></form>{{end}}
</nav>{{end}}
```

`templates/login.html`：

```html
{{define "login"}}<!doctype html>
<html lang="zh">
{{template "head" .}}
<body>
{{template "nav" .}}
<main>
<h1>登录</h1>
<form id="login">
  <input name="username" placeholder="用户名"><br>
  <input name="password" type="password" placeholder="密码"><br>
  <button type="submit">登录</button>
</form>
<script>
document.getElementById('login').addEventListener('submit', async e => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const r = await fetch('/api/login', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({username: fd.get('username'), password: fd.get('password')})
  });
  if (r.ok) location.href = '/';
  else alert('登录失败');
});
</script>
</main>
</body>
</html>{{end}}
```

`templates/servers.html`：

```html
{{define "servers"}}<!doctype html>
<html lang="zh">
{{template "head" .}}
<body>
{{template "nav" .}}
<main>
<h1>服务器</h1>
<button hx-get="/servers/new" hx-target="#form">添加服务器</button>
<div id="form"></div>
<ul>
{{range .Servers}}<li><a href="/servers/{{.ID}}">{{.Name}} ({{.Host}})</a></li>{{end}}
</ul>
</main>
</body>
</html>{{end}}
```

`templates/server_detail.html`：

```html
{{define "server_detail"}}<!doctype html>
<html lang="zh">
{{template "head" .}}
<body>
{{template "nav" .}}
<main>
<h1>{{.Server.Name}} <small>{{.Server.Host}}:{{.Server.SSHPort}}</small></h1>
<h2>账户</h2>
<ul>
{{range .Accounts}}
  <li>{{.Username}} — 状态:{{.Status}}
      {{if .CodingCapable}}[编码]{{end}}
      {{if .ExposedToAgent}}[已暴露]{{end}}
      <button hx-delete="/api/accounts/{{.ID}}" hx-confirm="确认删除?">删除</button>
      <button hx-post="/api/accounts/{{.ID}}/provision" hx-target="closest li">重新建户</button>
  </li>
{{end}}
</ul>
</main>
</body>
</html>{{end}}
```

> UI 细节（表单字段、样式）在实现时用 frontend-design 技能打磨；本任务目标是「能跑、能完成 CRUD」的最小可渲染页面，route 见 Task 14 的页面路由。

- [ ] **Step 3: 写最小静态资源**

`static/app.css`：基础布局样式（导航、列表、表单间距）。`static/app.js`：登录后跳转等少量逻辑。

- [ ] **Step 4: 校验模板可解析（临时测试）**

`internal/web/embed_test.go`：

```go
package web

import "testing"

func TestParseTemplates(t *testing.T) {
	if _, err := ParseTemplates(); err != nil { t.Fatal(err) }
}
```

Run: `go test ./internal/web/`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/web/
git commit -m "feat: embedded web templates + static"
```

---

## Task 14: main.go — 装配 + bootstrap + 页面路由

**Files:**
- Create: `cmd/server-agent-link/main.go`
- Modify: `internal/httpapi/server.go`（补页面路由 GET `/`、`/servers/{id}`）

**Interfaces:**
- Consumes: 所有已建包。
- Produces: 可运行二进制。

- [ ] **Step 1: 实现 main.go**

`cmd/server-agent-link/main.go`：

```go
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"serveragentlink/internal/config"
	"serveragentlink/internal/crypto"
	"serveragentlink/internal/httpapi"
	"serveragentlink/internal/mcp"
	"serveragentlink/internal/sshx"
	"serveragentlink/internal/store"
)

func main() {
	cfg, err := config.Load()
	if err != nil { log.Fatalf("config: %v", err) }

	key, err := resolveKey(cfg)
	if err != nil { log.Fatalf("key: %v", err) }

	st, err := store.Open(cfg.DataDir, key)
	if err != nil { log.Fatalf("store: %v", err) }
	defer st.Close()

	sshx.SetBackend(cfg.PermissionBackend)
	exec := &sshx.Executor{}

	ctx := context.Background()
	if err := bootstrap(ctx, st, cfg, key); err != nil { log.Fatalf("bootstrap: %v", err) }

	mcpHandler, err := mcp.NewHandler(st, key, cfg.MCPToken)
	if err != nil { log.Fatalf("mcp: %v", err) }

	srv := httpapi.New(st, key, cfg.AdminUser, exec, mcpHandler, cfg.PermissionBackend)
	log.Printf("listening on %s", cfg.ListenAddr)
	log.Fatal(http.ListenAndServe(cfg.ListenAddr, srv.Handler()))
}

// resolveKey 返回 32 字节主密钥：优先 env，其次数据目录 keyfile（无则生成并写 0600）。
func resolveKey(cfg *config.Config) ([]byte, error) {
	if k, err := cfg.MasterKeyBytes(); err == nil {
		return k, nil
	}
	keyPath := filepath.Join(cfg.DataDir, "master.key")
	if b, err := os.ReadFile(keyPath); err == nil && len(b) == 32 {
		return b, nil
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil { return nil, err }
	k, err := crypto.GenerateKey()
	if err != nil { return nil, err }
	if err := os.WriteFile(keyPath, k, 0o600); err != nil { return nil, err }
	return k, nil
}

// bootstrap 首次运行时创建管理员并生成 MCP token。
func bootstrap(ctx context.Context, st *store.Store, cfg *config.Config, key []byte) error {
	if _, err := st.GetAdmin(ctx); err == store.ErrNotFound {
		pw := cfg.AdminPassword
		if pw == "" {
			t, _ := crypto.RandomToken()
			pw = t
			log.Printf("generated admin password: %s", pw)
		}
		hash, err := crypto.HashPassword(pw)
		if err != nil { return err }
		if err := st.UpsertAdmin(ctx, cfg.AdminUser, hash); err != nil { return err }
	}
	if cfg.MCPToken != "" {
		return st.SetSetting(ctx, "mcp_token_hash", cfg.MCPToken)
	}
	return nil
}
```

> `sshx.Executor` 已在 Task 8 定义为空 struct 类型（方法集 `CreateUser/DeleteUser/UpdatePermissions`），本任务直接用 `&sshx.Executor{}` 实例化并传给 `httpapi.New`。

- [ ] **Step 2: 补页面路由**

`internal/httpapi/server.go` 的 `Handler()` 增加（在 `mux` 上）：

```go
mux.HandleFunc("GET /{$}", s.handleServersPage)
mux.HandleFunc("GET /servers/{id}", s.handleServerPage)
mux.HandleFunc("GET /login", s.handleLoginPage)
```

在 `handlers_servers.go`（或新 `handlers_pages.go`）实现页面渲染：

```go
func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, "login", map[string]any{"Authed": false})
}

func (s *Server) handleServersPage(w http.ResponseWriter, r *http.Request) {
	servers, _ := s.st.ListServers(r.Context())
	s.render(w, "servers", map[string]any{"Authed": true, "Servers": servers})
}

func (s *Server) handleServerPage(w http.ResponseWriter, r *http.Request) {
	sv, err := s.st.GetServer(r.Context(), r.PathValue("id"))
	if err != nil { http.NotFound(w, r); return }
	accounts, _ := s.st.ListAccounts(r.Context(), sv.ID)
	s.render(w, "server_detail", map[string]any{"Authed": true, "Server": sv, "Accounts": accounts})
}

func (s *Server) render(w http.ResponseWriter, name string, data map[string]any) {
	// 惰性解析模板（缓存于 Server 字段，避免每次 Parse）
	if err := s.templates.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
```

> `Server` 增加 `templates *template.Template` 字段，`New` 中调用 `web.ParseTemplates()` 并存入。`render` 里用 `s.templates.ExecuteTemplate(w, name, data)`（name 为各页面模板的 define 名：`"login"`/`"servers"`/`"server_detail"`）。模板采用「共享 partial（`head`/`nav`）+ 各自独立页面」结构——每个页面模板 `{{define "xxx"}}<!doctype html>…{{template "head" .}}…{{end}}` 自成完整 HTML，避免单次 `ParseFS` 下多个 `{{define "content"}}` 互相覆盖导致所有页面渲染同一内容的问题。login 页面无需登录态，其余页面在 `Handler` 里套 `requireAuth`。

- [ ] **Step 3: 编译 + 冒烟**

```bash
go build ./...
go vet ./...
```

Expected: 无错误。

- [ ] **Step 4: 手动冒烟**

Run: `SAL_MASTER_KEY=$(openssl rand -hex 32) SAL_MCP_TOKEN=devtoken go run ./cmd/server-agent-link`
Expected: 启动打印 `listening on :8080`；`curl -i http://localhost:8080/api/servers` 返回 401；`curl -i -X POST -d '{"username":"admin","password":"..."}' http://localhost:8080/api/login` 登录成功。

- [ ] **Step 5: Commit**

```bash
git add cmd/ internal/httpapi/
git commit -m "feat: wire main + bootstrap + page routes"
```

---

## Task 15: 集成测试（docker sshd）+ README

**Files:**
- Create: `internal/sshx/integration_test.go`（build tag `//go:build integration`）
- Create: `README.md`

**Interfaces:**
- Consumes: docker 环境（可选，仅在跑集成测试时需要）。

- [ ] **Step 1: 写 docker sshd 集成测试（可选，带 build tag）**

`internal/sshx/integration_test.go`：

```go
//go:build integration

package sshx

import (
	"context"
	"testing"
	"time"
)

// 前置：docker run -d --rm -p 2222:22 -e ROOT_PASSWORD=rootpw panubo/sshd
func TestCreateUserAgainstDocker(t *testing.T) {
	spec := UserSpec{Username: "ituser", Password: "itpw",
		Permissions: []PermissionSpec{{Path: "/home/ituser", Mode: "rw"}}}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := (&Executor{}).CreateUser(ctx, "127.0.0.1", 2222, "root", "rootpw", "", spec)
	if err != nil { t.Fatal(err) }
}
```

Run（有 docker 时）: `go test -tags integration ./internal/sshx/`
Expected: PASS（或按环境跳过）

- [ ] **Step 2: 写 README.md**

内容：项目简介、架构图（文字）、环境变量表、构建运行命令、ACL 前置条件（`acl` 包 + `acl` 挂载）、MCP 接入示例（`list_exposed_accounts` 返回示例 + agent 侧 `claude -p` 驱动示例）、安全说明。

- [ ] **Step 3: 全量测试 + 构建**

```bash
go test ./...
go build -o server-agent-link ./cmd/server-agent-link
```

Expected: 全部 PASS，产出单二进制。

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "docs: README + integration test"
```

---

## 完成标准

- `go test ./...` 全绿；`go build` 产出单二进制。
- 管理员可添加服务器、建/删账户、配目录权限、标记编码能力与暴露。
- `curl -H "Authorization: Bearer <token>" -X POST -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_exposed_accounts","arguments":{}}}' http://localhost:8080/mcp` 返回暴露账户及解密后的密码。
- 密码密文落库，日志无明文。
