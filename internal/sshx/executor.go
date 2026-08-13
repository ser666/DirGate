package sshx

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// commandTimeout 限制单条远程命令的执行时长；仅覆盖命令执行，
// TCP 拨号/握手另由 Dial 的 cfg.Timeout（10s）控制。
const commandTimeout = 60 * time.Second

type PermissionSpec struct {
	Path string
	Mode string // "rw" | "ro"
}

type UserSpec struct {
	Username    string
	Password    string
	Permissions []PermissionSpec
	Removed     []PermissionSpec // 更新权限时需撤销 ACL 的旧目录
}

// BuildCreateScript 生成幂等的建户脚本：用户已存在时跳过 useradd，
// 但始终重新执行 chpasswd 与权限授权，确保重试（如首次建户后 setfacl
// 失败）能补全密码与目录 ACL，而非静默跳过。
// 密码不写入脚本：chpasswd 从 stdin 读取 username:password，由 Executor
// 经加密通道写入，避免出现在远端命令行（ps）中。
func BuildCreateScript(u UserSpec) string {
	var b strings.Builder
	b.WriteString("set -e\n")
	b.WriteString(fmt.Sprintf("id %s >/dev/null 2>&1 || useradd -m -s /bin/bash %s\n", shq(u.Username), shq(u.Username)))
	b.WriteString("chpasswd\n")
	for _, p := range u.Permissions {
		b.WriteString(permLines(u.Username, p))
	}
	return b.String()
}

func permLines(username string, p PermissionSpec) string {
	if p.Mode == "rw" {
		return fmt.Sprintf("setfacl -m u:%s:rwx %s\nsetfacl -m d:u:%s:rwx %s\n",
			shq(username), shq(p.Path), shq(username), shq(p.Path))
	}
	return fmt.Sprintf("setfacl -m u:%s:rx %s\nsetfacl -m d:u:%s:rx %s\n",
		shq(username), shq(p.Path), shq(username), shq(p.Path))
}

func BuildDeleteScript(username string) string {
	return fmt.Sprintf("set -e\nid %s >/dev/null 2>&1 || exit 0\nuserdel -r %s\n", shq(username), shq(username))
}

func BuildUpdateScript(spec UserSpec) string {
	var b strings.Builder
	b.WriteString("set -e\n")
	for _, p := range spec.Removed {
		b.WriteString(revokeLines(spec.Username, p))
	}
	for _, p := range spec.Permissions {
		b.WriteString(permLines(spec.Username, p))
	}
	return b.String()
}

// revokeLines 撤销某目录上用户已有的 ACL。
// 用 `|| true` 容忍目标条目不存在，保持脚本幂等且不因 set -e 中断。
func revokeLines(username string, p PermissionSpec) string {
	return fmt.Sprintf("setfacl -x u:%s %s 2>/dev/null || true\nsetfacl -x d:u:%s %s 2>/dev/null || true\n",
		shq(username), shq(p.Path), shq(username), shq(p.Path))
}

// shq 用单引号包裹并转义内部单引号。
func shq(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

// Executor 为空结构体，方法集即建户/删户/改权限；便于 httpapi 层做接口注入与 fake。
type Executor struct{}

// CreateUser 建户并返回观察到的 SSH 主机指纹（供调用方回写 TOFU 记录）。
func (x *Executor) CreateUser(ctx context.Context, host string, port int, rootUser, rootPassword, knownHost string, spec UserSpec) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	c, fp, err := Dial(host, port, rootUser, rootPassword, knownHost)
	if err != nil {
		return "", err
	}
	defer c.Close()
	script := BuildCreateScript(spec)
	stdin := spec.Username + ":" + spec.Password + "\n"
	if _, err := c.RunStdin(ctx, script, stdin); err != nil {
		return "", fmt.Errorf("create user %s: %w", spec.Username, err)
	}
	return fp, nil
}

// DeleteUser 删户并返回 SSH 主机指纹（即使主机指纹此前为空，也应回写以完成 TOFU 固定）。
func (x *Executor) DeleteUser(ctx context.Context, host string, port int, rootUser, rootPassword, knownHost string, spec UserSpec) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	c, fp, err := Dial(host, port, rootUser, rootPassword, knownHost)
	if err != nil {
		return "", err
	}
	defer c.Close()
	if _, err := c.Run(ctx, BuildDeleteScript(spec.Username)); err != nil {
		return "", fmt.Errorf("delete user %s: %w", spec.Username, err)
	}
	return fp, nil
}

// UpdatePermissions 更新目录权限并返回 SSH 主机指纹。
func (x *Executor) UpdatePermissions(ctx context.Context, host string, port int, rootUser, rootPassword, knownHost string, spec UserSpec) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	c, fp, err := Dial(host, port, rootUser, rootPassword, knownHost)
	if err != nil {
		return "", err
	}
	defer c.Close()
	if _, err := c.Run(ctx, BuildUpdateScript(spec)); err != nil {
		return "", fmt.Errorf("update perms %s: %w", spec.Username, err)
	}
	return fp, nil
}
