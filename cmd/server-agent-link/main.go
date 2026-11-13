package main

import (
	"context"
	"fmt"
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
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if cfg.MCPToken == "" {
		log.Fatalf("SAL_MCP_TOKEN must be set (static Bearer key for the MCP endpoint)")
	}

	key, err := resolveKey(cfg)
	if err != nil {
		log.Fatalf("key: %v", err)
	}

	st, err := store.Open(cfg.DataDir, key)
	if err != nil {
		log.Fatalf("store: %v", err)
	}
	defer st.Close()

	exec := &sshx.Executor{}

	ctx := context.Background()
	if err := bootstrap(ctx, st, cfg); err != nil {
		log.Fatalf("bootstrap: %v", err)
	}

	mcpHandler, err := mcp.NewHandler(st, key, cfg.MCPToken)
	if err != nil {
		log.Fatalf("mcp: %v", err)
	}

	secureCookies := cfg.TLSCert != ""
	srv := httpapi.New(st, key, cfg.AdminUser, exec, mcpHandler, secureCookies)
	// 到期账户自动回收：每 10 分钟扫描，锁定到期 OS 账户并停止 MCP 暴露。
	srv.StartExpirySweeper(ctx)

	if cfg.TLSCert != "" {
		log.Printf("listening on %s (TLS)", cfg.ListenAddr)
		log.Fatal(http.ListenAndServeTLS(cfg.ListenAddr, cfg.TLSCert, cfg.TLSKey, srv.Handler()))
	}
	log.Printf("listening on %s (plaintext HTTP — set SAL_TLS_CERT/SAL_TLS_KEY for production)", cfg.ListenAddr)
	log.Fatal(http.ListenAndServe(cfg.ListenAddr, srv.Handler()))
}

// resolveKey 返回 32 字节主密钥：优先 env，其次数据目录 keyfile。
// 仅在「真·首次运行」（既无 keyfile 也无数据库）时才生成新密钥；
// 否则一律报错，避免用新密钥覆盖旧密钥导致历史密文永久不可解密。
func resolveKey(cfg *config.Config) ([]byte, error) {
	if cfg.MasterKeyHex != "" {
		return cfg.MasterKeyBytes()
	}
	keyPath := filepath.Join(cfg.DataDir, "master.key")
	if b, err := os.ReadFile(keyPath); err == nil {
		if len(b) != 32 {
			return nil, fmt.Errorf("master key file %s is corrupt (len=%d, want 32); refusing to overwrite", keyPath, len(b))
		}
		return b, nil
	}
	// keyfile 不存在：若数据库已存在，说明此前用 env 密钥（或 keyfile 被删）运行过，
	// 重新生成会导致旧密文无法解密，因此直接报错。
	if _, err := os.Stat(filepath.Join(cfg.DataDir, "server-agent-link.db")); err == nil {
		return nil, fmt.Errorf("no master key found but database exists in %s; set SAL_MASTER_KEY to the original key", cfg.DataDir)
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, err
	}
	k, err := crypto.GenerateKey()
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, k, 0o600); err != nil {
		return nil, err
	}
	return k, nil
}

// bootstrap 首次运行时创建管理员；未指定密码时生成随机密码并写入 0600 文件（不落 stdout/日志）。
func bootstrap(ctx context.Context, st *store.Store, cfg *config.Config) error {
	_, err := st.GetAdmin(ctx)
	if err == nil {
		return nil
	}
	if err != store.ErrNotFound {
		return err
	}
	pw := cfg.AdminPassword
	if pw == "" {
		pw, err = crypto.RandomToken()
		if err != nil {
			return err
		}
		pwPath := filepath.Join(cfg.DataDir, "admin-password.txt")
		if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(pwPath, []byte(pw+"\n"), 0o600); err != nil {
			return err
		}
		log.Printf("generated admin password written to %s", pwPath)
	}
	hash, err := crypto.HashPassword(pw)
	if err != nil {
		return err
	}
	return st.UpsertAdmin(ctx, cfg.AdminUser, hash)
}
