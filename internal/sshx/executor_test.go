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
	// 密码经 stdin 管道传给 chpasswd（而非作为独立命令行的明文参数）。
	if !strings.Contains(script, "| chpasswd") {
		t.Fatal("expected chpasswd via stdin pipe")
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
}
