package sshx

import (
	"strings"
	"testing"
)

func TestBuildCreateScriptACL(t *testing.T) {
	u := UserSpec{Username: "alice", Password: "pw",
		Permissions: []PermissionSpec{{Path: "/data/a", Mode: "rw"}, {Path: "/data/b", Mode: "ro"}}}
	script := BuildCreateScript(u)
	for _, want := range []string{
		"id 'alice'", "$SUDO useradd -m -s /bin/bash 'alice'", "$SUDO chpasswd",
		"$SUDO setfacl -m u:'alice':rwx '/data/a'", "$SUDO setfacl -m d:u:'alice':rwx '/data/a'",
		"$SUDO setfacl -m u:'alice':rx '/data/b'", "$SUDO setfacl -m d:u:'alice':rx '/data/b'",
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

func TestBuildCreateScriptIdempotent(t *testing.T) {
	// 用户已存在时跳过 useradd，但仍执行 chpasswd 与 ACL，避免重试后凭据/权限未生效。
	script := BuildCreateScript(UserSpec{Username: "alice", Permissions: []PermissionSpec{{Path: "/d", Mode: "rw"}}})
	if strings.Contains(script, "&& exit 0") {
		t.Fatalf("create script must not early-exit on existing user:\n%s", script)
	}
	if !strings.Contains(script, "id 'alice' >/dev/null 2>&1 || $SUDO useradd -m -s /bin/bash 'alice'") {
		t.Fatalf("useradd must be guarded by || (idempotent create):\n%s", script)
	}
	// chpasswd 与 ACL 必须位于 useradd 之后且始终存在。
	if strings.Index(script, "chpasswd") < strings.Index(script, "useradd") {
		t.Fatalf("chpasswd must follow useradd:\n%s", script)
	}
	if !strings.Contains(script, "$SUDO setfacl -m u:'alice':rwx '/d'") {
		t.Fatalf("missing ACL line:\n%s", script)
	}
}

// 建户脚本必须逆转到期锁定：usermod -U（解锁密码）+ 恢复 /bin/bash。
func TestBuildCreateScriptReversesLock(t *testing.T) {
	script := BuildCreateScript(UserSpec{Username: "alice"})
	for _, want := range []string{
		"$SUDO usermod -U 'alice' 2>/dev/null || true",
		"$SUDO usermod -s /bin/bash 'alice'",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("create script missing lock-reversal %q:\n%s", want, script)
		}
	}
	// 解锁须在 chpasswd 之前（chpasswd 重设密码后不再需要 -U，但顺序上先解锁更稳）。
	if strings.Index(script, "usermod -U") > strings.Index(script, "chpasswd") {
		t.Fatalf("usermod -U must precede chpasswd:\n%s", script)
	}
}

func TestBuildCreateScriptQuotesPasswordOffCommandLine(t *testing.T) {
	// 即使密码含单引号等 shell 特殊字符，也不得进入脚本。
	u := UserSpec{Username: "alice", Password: "p@ss'; rm -rf /tmp/pwn; echo '", Permissions: nil}
	script := BuildCreateScript(u)
	if strings.Contains(script, u.Password) {
		t.Fatalf("password leaked into script:\n%s", script)
	}
}

func TestBuildDeleteScript(t *testing.T) {
	revoked := []PermissionSpec{{Path: "/data/a", Mode: "rw"}, {Path: "/data/b", Mode: "ro"}}
	script := BuildDeleteScript("alice", revoked)
	if !strings.Contains(script, "$SUDO userdel -r 'alice'") {
		t.Fatalf("missing userdel:\n%s", script)
	}
	// 删户前必须逐目录撤销 ACL，避免孤儿权限残留。
	for _, want := range []string{
		"$SUDO setfacl -x u:'alice' '/data/a'",
		"$SUDO setfacl -x d:u:'alice' '/data/a'",
		"$SUDO setfacl -x u:'alice' '/data/b'",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("delete script missing revoke %q:\n%s", want, script)
		}
	}
	if strings.Index(script, "setfacl -x") > strings.Index(script, "userdel") {
		t.Fatalf("revoke must precede userdel:\n%s", script)
	}
	// 幂等：用户不存在时静默成功（exit 0），避免重试时误报失败。
	if !strings.Contains(script, "id 'alice' >/dev/null 2>&1 || exit 0") {
		t.Fatalf("delete script not idempotent:\n%s", script)
	}
}

func TestBuildLockScript(t *testing.T) {
	script := BuildLockScript("alice")
	for _, want := range []string{
		"$SUDO usermod -L 'alice'",
		"$SUDO usermod -s /sbin/nologin 'alice'",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("lock script missing %q:\n%s", want, script)
		}
	}
	// 不删数据：锁定脚本绝不包含 userdel。
	if strings.Contains(script, "userdel") {
		t.Fatalf("lock script must not delete:\n%s", script)
	}
	// 幂等：用户不存在时静默成功。
	if !strings.Contains(script, "id 'alice' >/dev/null 2>&1 || exit 0") {
		t.Fatalf("lock script not idempotent:\n%s", script)
	}
}

func TestBuildUpdateScriptRevokesRemoved(t *testing.T) {
	spec := UserSpec{
		Username:    "alice",
		Removed:     []PermissionSpec{{Path: "/data/a", Mode: "rw"}},
		Permissions: []PermissionSpec{{Path: "/data/b", Mode: "ro"}},
	}
	script := BuildUpdateScript(spec)
	// 撤销旧目录 ACL（幂等，容忍不存在）。
	for _, want := range []string{
		"$SUDO setfacl -x u:'alice' '/data/a'",
		"$SUDO setfacl -x d:u:'alice' '/data/a'",
		// 新增目录 ACL。
		"$SUDO setfacl -m u:'alice':rx '/data/b'",
		"$SUDO setfacl -m d:u:'alice':rx '/data/b'",
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

func TestBuildScriptsAutoSudo(t *testing.T) {
	// 三种脚本都须包含「非 root 则 sudo -n 提权」的探测，使以普通 sudo 账户（非 uid 0）
	// 登录时 useradd/chpasswd/setfacl/userdel 仍能获得特权。
	scripts := []string{
		BuildCreateScript(UserSpec{Username: "alice", Permissions: []PermissionSpec{{Path: "/d", Mode: "rw"}}}),
		BuildDeleteScript("alice", nil),
		BuildUpdateScript(UserSpec{Username: "alice", Permissions: []PermissionSpec{{Path: "/d", Mode: "rw"}}}),
	}
	for i, s := range scripts {
		if !strings.Contains(s, `if [ "$(id -u)" != "0" ]; then SUDO="sudo -n"; fi`) {
			t.Fatalf("script[%d] missing sudo probe:\n%s", i, s)
		}
		if !strings.Contains(s, "$SUDO") {
			t.Fatalf("script[%d] never uses $SUDO:\n%s", i, s)
		}
	}
}

func TestBuildAttachPermScript(t *testing.T) {
	script := BuildAttachPermScript(
		[]PermissionSpec{{Path: "/home/dev/a", Mode: "rw"}},
		[]PermissionSpec{{Path: "/home/dev/old", Mode: "ro"}},
	)
	// plain 模式无 sudo：setfacl 裸调用（内核限自己拥有的目录），用户取自 $LOGNAME
	for _, want := range []string{
		"setfacl -x u:$LOGNAME '/home/dev/old'",
		"setfacl -x d:u:$LOGNAME '/home/dev/old'",
		"setfacl -m u:$LOGNAME:rwx '/home/dev/a'",
		"setfacl -m d:u:$LOGNAME:rwx '/home/dev/a'",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("attach perm script missing %q:\n%s", want, script)
		}
	}
	if strings.Contains(script, "$SUDO") {
		t.Fatalf("attach script must not use sudo:\n%s", script)
	}
	// 撤销先于授予
	if strings.Index(script, "setfacl -x") > strings.Index(script, "setfacl -m") {
		t.Fatalf("revoke must precede grant:\n%s", script)
	}
}

func TestBuildAttachLockScript(t *testing.T) {
	script := BuildAttachLockScript([]PermissionSpec{{Path: "/home/dev/a", Mode: "rw"}})
	// setfacl -b 清全部 ACL（含默认），幂等容忍不存在
	if !strings.Contains(script, "setfacl -b '/home/dev/a'") {
		t.Fatalf("lock script missing setfacl -b:\n%s", script)
	}
	if strings.Contains(script, "usermod") || strings.Contains(script, "userdel") {
		t.Fatalf("plain lock must not touch OS account:\n%s", script)
	}
}
