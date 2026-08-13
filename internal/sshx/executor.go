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
	Removed     []PermissionSpec // 更新权限时需撤销 ACL/组权限的旧目录
}

// BuildCreateScript 生成幂等的建户 shell 脚本。
// 密码不写入脚本：脚本内的 chpasswd 从 stdin 读取 username:password，
// 由 Executor 经加密通道写入，避免出现在远端命令行（ps）中。
func BuildCreateScript(u UserSpec, backend string) string {
	var b strings.Builder
	b.WriteString("set -e\n")
	b.WriteString(fmt.Sprintf("id %s >/dev/null 2>&1 && exit 0\n", shq(u.Username))) // 已存在则跳过
	b.WriteString(fmt.Sprintf("useradd -m -s /bin/bash %s\n", shq(u.Username)))
	b.WriteString("chpasswd\n")
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
		if p.Mode == "rw" {
			perm = "rwx"
		}
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
	return fmt.Sprintf("set -e\nid %s >/dev/null 2>&1 || exit 0\nuserdel -r %s\n", shq(username), shq(username))
}

func BuildUpdateScript(spec UserSpec, backend string) string {
	var b strings.Builder
	b.WriteString("set -e\n")
	for _, p := range spec.Removed {
		b.WriteString(revokeLines(spec.Username, p, backend))
	}
	for _, p := range spec.Permissions {
		b.WriteString(permLines(spec.Username, p, backend))
	}
	return b.String()
}

// revokeLines 撤销某目录上用户已有的 ACL（或同名组）。
// 用 `|| true` 容忍目标条目不存在，保持脚本幂等且不因 set -e 中断。
func revokeLines(username string, p PermissionSpec, backend string) string {
	if backend == "group" {
		return fmt.Sprintf("groupdel %s 2>/dev/null || true\n", shq(username))
	}
	return fmt.Sprintf("setfacl -x u:%s %s 2>/dev/null || true\nsetfacl -x d:u:%s %s 2>/dev/null || true\n",
		shq(username), shq(p.Path), shq(username), shq(p.Path))
}

// shq 用单引号包裹并转义内部单引号。
func shq(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

// backendGlobal 为全局权限后端（acl | group），main 在启动时用 SetBackend 设置。
var backendGlobal = "acl"

// SetBackend 设置全局权限后端。
func SetBackend(b string) { backendGlobal = b }

// Executor 为空结构体，方法集即建户/删户/改权限；便于 httpapi 层做接口注入与 fake。
type Executor struct{}

func (x *Executor) CreateUser(ctx context.Context, host string, port int, rootUser, rootPassword, knownHost string, spec UserSpec) (string, error) {
	c, fp, err := Dial(host, port, rootUser, rootPassword, knownHost)
	if err != nil {
		return "", err
	}
	defer c.Close()
	script := BuildCreateScript(spec, backendGlobal)
	stdin := spec.Username + ":" + spec.Password + "\n"
	if _, err := c.RunStdin(ctx, script, stdin); err != nil {
		return "", fmt.Errorf("create user %s: %w", spec.Username, err)
	}
	return fp, nil
}

func (x *Executor) DeleteUser(ctx context.Context, host string, port int, rootUser, rootPassword, knownHost string, spec UserSpec) error {
	c, _, err := Dial(host, port, rootUser, rootPassword, knownHost)
	if err != nil {
		return err
	}
	defer c.Close()
	if _, err := c.Run(ctx, BuildDeleteScript(spec.Username)); err != nil {
		return fmt.Errorf("delete user %s: %w", spec.Username, err)
	}
	return nil
}

func (x *Executor) UpdatePermissions(ctx context.Context, host string, port int, rootUser, rootPassword, knownHost string, spec UserSpec) error {
	c, _, err := Dial(host, port, rootUser, rootPassword, knownHost)
	if err != nil {
		return err
	}
	defer c.Close()
	if _, err := c.Run(ctx, BuildUpdateScript(spec, backendGlobal)); err != nil {
		return fmt.Errorf("update perms %s: %w", spec.Username, err)
	}
	return nil
}
