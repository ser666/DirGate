package httpapi

import (
	"context"
	"fmt"
	"testing"
	"time"

	"serveragentlink/internal/store"
)

// sweepExpired 应锁定到期账户：调 LockUser、置 status=locked，且锁定后不再重复处理。
func TestSweepExpiredLocksAccount(t *testing.T) {
	srv := newTestServer(t)
	fx := &fakeExec{}
	srv.exec = fx
	ctx := context.Background()
	sv, _ := srv.st.CreateServer(ctx, "s1", "10.0.0.1", 22, "root", "rp")

	a, _ := srv.st.CreateAccount(ctx, sv.ID, "alice", "pw", true)
	a.ExpiresAt = time.Now().UTC().Add(-time.Minute).Format(time.RFC3339) // 已过期
	if err := srv.st.UpdateAccount(ctx, *a); err != nil {
		t.Fatal(err)
	}
	b, _ := srv.st.CreateAccount(ctx, sv.ID, "bob", "pw", true) // 永不到期

	srv.sweepExpired(ctx)

	if fx.locked != 1 {
		t.Fatalf("LockUser calls = %d, want 1", fx.locked)
	}
	got, _ := srv.st.GetAccount(ctx, a.ID)
	if got.Status != store.StatusLocked {
		t.Fatalf("alice status = %q, want locked", got.Status)
	}
	gotB, _ := srv.st.GetAccount(ctx, b.ID)
	if gotB.Status == store.StatusLocked {
		t.Fatal("bob must not be locked (no expiry)")
	}

	// 第二轮扫描不再重复锁定。
	srv.sweepExpired(ctx)
	if fx.locked != 1 {
		t.Fatalf("LockUser calls after resweep = %d, want 1", fx.locked)
	}
}

// 锁定失败时标记 error，下轮仍会重试。
func TestSweepExpiredRetriesOnFailure(t *testing.T) {
	srv := newTestServer(t)
	srv.exec = &failExec{err: fmt.Errorf("ssh down")}
	ctx := context.Background()
	sv, _ := srv.st.CreateServer(ctx, "s1", "10.0.0.1", 22, "root", "rp")

	a, _ := srv.st.CreateAccount(ctx, sv.ID, "alice", "pw", true)
	a.ExpiresAt = time.Now().UTC().Add(-time.Minute).Format(time.RFC3339)
	_ = srv.st.UpdateAccount(ctx, *a)

	srv.sweepExpired(ctx)
	got, _ := srv.st.GetAccount(ctx, a.ID)
	if got.Status != store.StatusError {
		t.Fatalf("status = %q, want error", got.Status)
	}

	// 恢复连通后重试成功 → locked。
	srv.exec = &fakeExec{}
	srv.sweepExpired(ctx)
	got, _ = srv.st.GetAccount(ctx, a.ID)
	if got.Status != store.StatusLocked {
		t.Fatalf("status after retry = %q, want locked", got.Status)
	}
}
