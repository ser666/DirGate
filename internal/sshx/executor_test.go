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
		"id 'alice'", "useradd -m -s /bin/bash 'alice'", "chpasswd",
		"setfacl -m u:'alice':rwx '/data/a'", "setfacl -m d:u:'alice':rwx '/data/a'",
		"setfacl -m u:'alice':rx '/data/b'", "setfacl -m d:u:'alice':rx '/data/b'",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("script missing %q:\n%s", want, script)
		}
	}
	// 密码绝不写入脚本（由 Executor 经 stdin 传 chpasswd），避免命令行/ps 泄露。
	if strings.Contains(script, u.Password) {
		t.Fatalf("password must not appear in script:\n%s", script)
	}
}

func TestBuildCreateScriptQuotesPasswordOffCommandLine(t *testing.T) {
	// 即使密码含单引号等 shell 特殊字符，也不得进入脚本。
	u := UserSpec{Username: "alice", Password: "p@ss'; rm -rf /tmp/pwn; echo '", Permissions: nil}
	script := BuildCreateScript(u, "acl")
	if strings.Contains(script, u.Password) {
		t.Fatalf("password leaked into script:\n%s", script)
	}
}

func TestBuildCreateScriptGroup(t *testing.T) {
	u := UserSpec{Username: "bob", Password: "x", Permissions: []PermissionSpec{{Path: "/d", Mode: "rw"}}}
	script := BuildCreateScript(u, "group")
	if !strings.Contains(script, "chgrp 'bob' '/d'") {
		t.Fatalf("group backend missing chgrp:\n%s", script)
	}
}

func TestBuildDeleteScript(t *testing.T) {
	script := BuildDeleteScript("alice")
	if !strings.Contains(script, "userdel -r 'alice'") {
		t.Fatalf("missing userdel:\n%s", script)
	}
	// 幂等：用户不存在时静默成功（exit 0），避免重试时误报失败。
	if !strings.Contains(script, "id 'alice' >/dev/null 2>&1 || exit 0") {
		t.Fatalf("delete script not idempotent:\n%s", script)
	}
}

func TestBuildUpdateScriptRevokesRemoved(t *testing.T) {
	spec := UserSpec{
		Username:    "alice",
		Removed:     []PermissionSpec{{Path: "/data/a", Mode: "rw"}},
		Permissions: []PermissionSpec{{Path: "/data/b", Mode: "ro"}},
	}
	script := BuildUpdateScript(spec, "acl")
	// 撤销旧目录 ACL（幂等，容忍不存在）。
	for _, want := range []string{
		"setfacl -x u:'alice' '/data/a'",
		"setfacl -x d:u:'alice' '/data/a'",
		// 新增目录 ACL。
		"setfacl -m u:'alice':rx '/data/b'",
		"setfacl -m d:u:'alice':rx '/data/b'",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("update script missing %q:\n%s", want, script)
		}
	}
	// 撤销行必须先于新增行，避免同一目录先加后删。
	if strings.Index(script, "setfacl -x") > strings.Index(script, "setfacl -m") {
		t.Fatalf("revoke must precede grant:\n%s", script)
	}
}

func TestBuildUpdateScriptRevokesRemovedGroup(t *testing.T) {
	spec := UserSpec{Username: "bob", Removed: []PermissionSpec{{Path: "/d", Mode: "rw"}}}
	script := BuildUpdateScript(spec, "group")
	if !strings.Contains(script, "groupdel 'bob' 2>/dev/null || true") {
		t.Fatalf("group backend missing groupdel:\n%s", script)
	}
}
