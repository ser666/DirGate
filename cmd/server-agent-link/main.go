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

	sshx.SetBackend(cfg.PermissionBackend)
	exec := &sshx.Executor{}

	ctx := context.Background()
	if err := bootstrap(ctx, st, cfg); err != nil {
		log.Fatalf("bootstrap: %v", err)
	}

	mcpHandler, err := mcp.NewHandler(st, key, cfg.MCPToken)
	if err != nil {
		log.Fatalf("mcp: %v", err)
	}

	srv := httpapi.New(st, key, cfg.AdminUser, exec, mcpHandler, cfg.PermissionBackend)
	log.Printf("listening on %s", cfg.ListenAddr)
	log.Fatal(http.ListenAndServe(cfg.ListenAddr, srv.Handler()))
}

// resolveKey 返回 32 字节主密钥：优先 env，其次数据目录 keyfile（无则生成并写 0600）。
// 若 env 已设置但非法（hex/长度错误），返回错误而非静默回退，避免旧密文无法解密。
func resolveKey(cfg *config.Config) ([]byte, error) {
	if cfg.MasterKeyHex != "" {
		return cfg.MasterKeyBytes()
	}
	keyPath := filepath.Join(cfg.DataDir, "master.key")
	if b, err := os.ReadFile(keyPath); err == nil && len(b) == 32 {
		return b, nil
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
