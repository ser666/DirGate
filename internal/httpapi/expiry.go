package httpapi

import (
	"context"
	"log"
	"time"
)

// StartExpirySweeper 启动到期回收循环：每 10 分钟扫描一次已到期且未锁定的账户，
// SSH 到目标服务器锁定 OS 用户（usermod -L + nologin，不删数据），并把账户标记为 locked。
// 锁定而非删除：管理员可在 UI 看到 locked 状态后自行决定删除或续期（改 expires_at 后「重新建户」即恢复）。
func (s *Server) StartExpirySweeper(ctx context.Context) {
	go func() {
		t := time.NewTicker(10 * time.Minute)
		defer t.Stop()
		for {
			s.sweepExpired(ctx)
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
}

func (s *Server) sweepExpired(ctx context.Context) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	accounts, err := s.st.ListExpiringAccounts(ctx, now)
	if err != nil {
		log.Printf("expiry sweeper: list: %v", err)
		return
	}
	for _, a := range accounts {
		s.lockExpired(ctx, a.ID, a.Username, a.ServerID)
	}
}

func (s *Server) lockExpired(ctx context.Context, accountID, username, serverID string) {
	sv, err := s.st.GetServer(ctx, serverID)
	if err != nil {
		log.Printf("expiry sweeper: account %s: get server: %v", username, err)
		return
	}
	rootPw, err := s.st.Decrypt(sv.RootPasswordEnc)
	if err != nil {
		log.Printf("expiry sweeper: account %s: decrypt: %v", username, err)
		return
	}
	fp, err := s.exec.LockUser(ctx, sv.Host, sv.SSHPort, sv.RootUser, string(rootPw), sv.HostKey, username)
	if err != nil {
		// 锁定失败保留 error 状态记录原因，下轮扫描重试（ListExpiringAccounts 会再返回它）。
		log.Printf("expiry sweeper: lock %s: %v", username, err)
		_ = s.st.MarkAccountError(ctx, accountID, "expiry lock failed: "+err.Error())
		return
	}
	s.persistHostKey(ctx, sv, fp)
	if err := s.st.MarkAccountLocked(ctx, accountID, "expired at "+time.Now().UTC().Format(time.RFC3339)); err != nil {
		log.Printf("expiry sweeper: mark locked %s: %v", username, err)
		return
	}
	log.Printf("audit user=system action=account.lock object=%s %s (expired)", accountID, username)
}
