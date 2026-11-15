package store

import (
	"context"
	"testing"
)

func TestAccountCRUDAndPermissions(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	sv, _ := s.CreateServer(ctx, "s1", "10.0.0.1", 22, "root", "rp")

	a, err := s.CreateAccount(ctx, sv.ID, "alice", "alicepw", true)
	if err != nil {
		t.Fatal(err)
	}
	if a.Status != StatusPending {
		t.Fatalf("status=%q", a.Status)
	}

	perms := []DirectoryPermission{
		{Path: "/data/a", Mode: ModeReadWrite},
		{Path: "/data/b", Mode: ModeReadOnly},
	}
	if err := s.SetPermissions(ctx, a.ID, perms); err != nil {
		t.Fatal(err)
	}
	got, _ := s.ListPermissions(ctx, a.ID)
	if len(got) != 2 {
		t.Fatalf("perms len=%d", len(got))
	}

	// 覆盖式替换
	if err := s.SetPermissions(ctx, a.ID, perms[:1]); err != nil {
		t.Fatal(err)
	}
	got, _ = s.ListPermissions(ctx, a.ID)
	if len(got) != 1 || got[0].Path != "/data/a" {
		t.Fatalf("replace failed: %+v", got)
	}

	now := "2026-01-01T00:00:00Z"
	exposed, _ := s.ListExposedAccounts(ctx, now)
	if len(exposed) != 1 {
		t.Fatalf("exposed len=%d", len(exposed))
	}
	if exposed[0].Username != "alice" || len(exposed[0].Directories) != 1 {
		t.Fatalf("bad exposed: %+v", exposed[0])
	}

	// 取消暴露后不再返回
	a.ExposedToAgent = false
	_ = s.UpdateAccount(ctx, *a)
	exposed, _ = s.ListExposedAccounts(ctx, now)
	if len(exposed) != 0 {
		t.Fatalf("expected 0 exposed")
	}
	a.ExposedToAgent = true
	_ = s.UpdateAccount(ctx, *a)

	// 到期账户不再暴露
	a.ExpiresAt = "2025-12-31T23:59:59Z"
	_ = s.UpdateAccount(ctx, *a)
	exposed, _ = s.ListExposedAccounts(ctx, now)
	if len(exposed) != 0 {
		t.Fatalf("expected expired account hidden, got %d", len(exposed))
	}

	if err := s.DeleteAccount(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetAccount(ctx, a.ID); err == nil {
		t.Fatal("expected not found")
	}
}

// ExposedRevision 返回暴露账户的最大 updated_at；改密/翻转开关后 revision 变化。
func TestExposedRevision(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	sv, _ := s.CreateServer(ctx, "s1", "10.0.0.1", 22, "root", "rp")

	a, _ := s.CreateAccount(ctx, sv.ID, "alice", "pw", true)
	rev1, err := s.ExposedRevision(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rev1 == "" {
		t.Fatal("exposed account must yield non-empty revision")
	}

	// 翻转暴露开关 → revision 变化
	a.ExposedToAgent = !a.ExposedToAgent
	_ = s.UpdateAccount(ctx, *a)
	rev2, _ := s.ExposedRevision(ctx)
	if rev2 == rev1 {
		t.Fatal("revision must change after exposure toggle")
	}

	// 停用服务器 → 无暴露账户 → 空串
	sv.Enabled = false
	_ = s.UpdateServer(ctx, *sv)
	rev3, _ := s.ExposedRevision(ctx)
	if rev3 != "" {
		t.Fatalf("no exposed accounts should give empty revision, got %q", rev3)
	}
}
