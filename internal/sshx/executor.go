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

// sudoProbe 在脚本开头判定当前 SSH 登录身份：root（uid 0）直接执行，否则用 `sudo -n` 提权。
// 这样既能以真实 root 运行（不依赖 sudo 是否安装），也能以带 sudo 权限的普通账户运行。
// `-n` 非交互模式：若 sudo 需要密码则立即报错，避免在无 TTY 的 exec 通道里读取 stdin 提示密码、
// 从而与 chpasswd 的「username:password」stdin 输入相混淆。
const sudoProbe = `SUDO=""
if [ "$(id -u)" != "0" ]; then SUDO="sudo -n"; fi
`

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

// BuildCreateScript 生成幂等建户脚本。密码不写入脚本：chpasswd 从 stdin 读
// username:password（由 Executor 经加密通道写入），避免出现在远端命令行（ps）。
// 用户已存在时跳过 useradd 但重跑 chpasswd 与 ACL，保证重试能补全未完成的步骤。
func BuildCreateScript(u UserSpec) string {
	var b strings.Builder
	b.WriteString("set -e\n")
	b.WriteString(sudoProbe)
	b.WriteString(fmt.Sprintf("id %s >/dev/null 2>&1 || $SUDO useradd -m -s /bin/bash %s\n", shq(u.Username), shq(u.Username)))
	b.WriteString("$SUDO chpasswd\n")
	for _, p := range u.Permissions {
		b.WriteString(permLines(u.Username, p))
	}
	return b.String()
}

func permLines(username string, p PermissionSpec) string {
	if p.Mode == "rw" {
		return fmt.Sprintf("$SUDO setfacl -m u:%s:rwx %s\n$SUDO setfacl -m d:u:%s:rwx %s\n",
			shq(username), shq(p.Path), shq(username), shq(p.Path))
	}
	return fmt.Sprintf("$SUDO setfacl -m u:%s:rx %s\n$SUDO setfacl -m d:u:%s:rx %s\n",
		shq(username), shq(p.Path), shq(username), shq(p.Path))
}

// BuildDeleteScript 生成删户脚本：先逐目录撤销 ACL（避免孤儿权限残留在被授权目录上），
// 再删除用户。用户不存在时静默成功，保持幂等重试。
func BuildDeleteScript(username string, revoked []PermissionSpec) string {
	var b strings.Builder
	b.WriteString("set -e\n")
	b.WriteString(sudoProbe)
	b.WriteString(fmt.Sprintf("id %s >/dev/null 2>&1 || exit 0\n", shq(username)))
	for _, p := range revoked {
		b.WriteString(revokeLines(username, p))
	}
	b.WriteString(fmt.Sprintf("$SUDO userdel -r %s\n", shq(username)))
	return b.String()
}

// BuildLockScript 生成锁定脚本：usermod -L 封密码 + usermod -s /sbin/nologin 封登录 shell，
// 不删除数据，供账户到期回收；可被「重新建户」逆转（usermod -U + 恢复 bash）。
func BuildLockScript(username string) string {
	var b strings.Builder
	b.WriteString("set -e\n")
	b.WriteString(sudoProbe)
	b.WriteString(fmt.Sprintf("id %s >/dev/null 2>&1 || exit 0\n", shq(username)))
	b.WriteString(fmt.Sprintf("$SUDO usermod -L %s\n", shq(username)))
	b.WriteString("$SUDO usermod -s /sbin/nologin " + shq(username) + "\n")
	return b.String()
}

func BuildUpdateScript(spec UserSpec) string {
	var b strings.Builder
	b.WriteString("set -e\n")
	b.WriteString(sudoProbe)
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
	return fmt.Sprintf("$SUDO setfacl -x u:%s %s 2>/dev/null || true\n$SUDO setfacl -x d:u:%s %s 2>/dev/null || true\n",
		shq(username), shq(p.Path), shq(username), shq(p.Path))
}

// shq 用单引号包裹并转义内部单引号。
func shq(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

// Executor 为空结构体，方法集即建户/删户/改权限/连通性测试；便于 httpapi 层做接口注入与 fake。
type Executor struct{}

// TestConnection 拨号并执行一条无害命令，验证主机可达、root 凭据正确、主机指纹匹配，
// 返回观察到的 SSH 主机指纹（供调用方回写 TOFU 记录）。不创建任何用户。
func (x *Executor) TestConnection(ctx context.Context, host string, port int, rootUser, rootPassword, knownHost string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	c, fp, err := Dial(host, port, rootUser, rootPassword, knownHost)
	if err != nil {
		return "", err
	}
	defer c.Close()
	if _, err := c.Run(ctx, "echo ok"); err != nil {
		return "", fmt.Errorf("test connection: %w", err)
	}
	return fp, nil
}

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

// DeleteUser 删户（先撤销逐目录 ACL）并返回 SSH 主机指纹（即使指纹此前为空，也应回写以完成 TOFU 固定）。
func (x *Executor) DeleteUser(ctx context.Context, host string, port int, rootUser, rootPassword, knownHost string, spec UserSpec) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	c, fp, err := Dial(host, port, rootUser, rootPassword, knownHost)
	if err != nil {
		return "", err
	}
	defer c.Close()
	if _, err := c.Run(ctx, BuildDeleteScript(spec.Username, spec.Permissions)); err != nil {
		return "", fmt.Errorf("delete user %s: %w", spec.Username, err)
	}
	return fp, nil
}

// LockUser 锁定 OS 用户（封密码 + nologin），供到期回收，不删数据；「重新建户」可逆转。
func (x *Executor) LockUser(ctx context.Context, host string, port int, rootUser, rootPassword, knownHost, username string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	c, fp, err := Dial(host, port, rootUser, rootPassword, knownHost)
	if err != nil {
		return "", err
	}
	defer c.Close()
	if _, err := c.Run(ctx, BuildLockScript(username)); err != nil {
		return "", fmt.Errorf("lock user %s: %w", username, err)
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
