package store

import (
	"context"
	"testing"
)

func TestAccountCRUDAndPermissions(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	sv, _ := s.CreateServer(ctx, "s1", "10.0.0.1", 22, "root", "rp")

	a, err := s.CreateAccount(ctx, sv.ID, "alice", "alicepw", true, true)
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

	exposed, _ := s.ListExposedAccounts(ctx)
	if len(exposed) != 1 {
		t.Fatalf("exposed len=%d", len(exposed))
	}
	if exposed[0].Username != "alice" || len(exposed[0].Directories) != 1 {
		t.Fatalf("bad exposed: %+v", exposed[0])
	}

	// 取消暴露后不再返回
	a.ExposedToAgent = false
	_ = s.UpdateAccount(ctx, *a)
	exposed, _ = s.ListExposedAccounts(ctx)
	if len(exposed) != 0 {
		t.Fatalf("expected 0 exposed")
	}

	if err := s.DeleteAccount(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetAccount(ctx, a.ID); err == nil {
		t.Fatal("expected not found")
	}
}
