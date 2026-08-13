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
	if _, err := c.Run(ctx, script); err != nil {
		return "", fmt.Errorf("create user %s: %w", spec.Username, err)
	}
	return fp, nil
}

func (x *Executor) DeleteUser(ctx context.Context, host string, port int, rootUser, rootPassword string, spec UserSpec) error {
	c, _, err := Dial(host, port, rootUser, rootPassword, "")
	if err != nil {
		return err
	}
	defer c.Close()
	if _, err := c.Run(ctx, BuildDeleteScript(spec.Username)); err != nil {
		return fmt.Errorf("delete user %s: %w", spec.Username, err)
	}
	return nil
}

func (x *Executor) UpdatePermissions(ctx context.Context, host string, port int, rootUser, rootPassword string, spec UserSpec) error {
	c, _, err := Dial(host, port, rootUser, rootPassword, "")
	if err != nil {
		return err
	}
	defer c.Close()
	if _, err := c.Run(ctx, BuildUpdateScript(spec.Username, spec.Permissions, backendGlobal)); err != nil {
		return fmt.Errorf("update perms %s: %w", spec.Username, err)
	}
	return nil
}
