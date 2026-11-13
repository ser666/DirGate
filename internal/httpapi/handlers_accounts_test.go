package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"serveragentlink/internal/sshx"
	"serveragentlink/internal/store"
)

type fakeExec struct {
	created   int
	updated   *sshx.UserSpec
	deleted   int
	tested    int
	locked    int
	probed    string // ProbeMode 返回值
	attached  int    // AttachVerify 调用次数
	attachSet int    // AttachSetPermissions 调用次数
	attachLk  int    // AttachLock 调用次数
}

func (f *fakeExec) CreateUser(ctx context.Context, host string, port int, rootUser, rootPassword, knownHost string, spec sshx.UserSpec) (string, error) {
	f.created++
	return "fp", nil
}
func (f *fakeExec) DeleteUser(ctx context.Context, host string, port int, rootUser, rootPassword, knownHost string, spec sshx.UserSpec) (string, error) {
	f.deleted++
	return "fp", nil
}
func (f *fakeExec) UpdatePermissions(ctx context.Context, host string, port int, rootUser, rootPassword, knownHost string, spec sshx.UserSpec) (string, error) {
	f.updated = &spec
	return "fp", nil
}
func (f *fakeExec) TestConnection(ctx context.Context, host string, port int, rootUser, rootPassword, knownHost string) (string, error) {
	f.tested++
	return "fp", nil
}
func (f *fakeExec) LockUser(ctx context.Context, host string, port int, rootUser, rootPassword, knownHost, username string) (string, error) {
	f.locked++
	return "fp", nil
}
func (f *fakeExec) ProbeMode(ctx context.Context, host string, port int, adminUser, adminPassword, knownHost string) (string, string, error) {
	return f.probed, "fp", nil
}
func (f *fakeExec) AttachVerify(ctx context.Context, host string, port int, username, password, knownHost string) (string, error) {
	f.attached++
	return "fp", nil
}
func (f *fakeExec) AttachSetPermissions(ctx context.Context, host string, port int, adminUser, adminPassword, knownHost string, granted, removed []sshx.PermissionSpec) (string, error) {
	f.attachSet++
	return "fp", nil
}
func (f *fakeExec) AttachLock(ctx context.Context, host string, port int, adminUser, adminPassword, knownHost string, revoked []sshx.PermissionSpec) (string, error) {
	f.attachLk++
	return "fp", nil
}

type failExec struct{ err error }

func (f *failExec) CreateUser(ctx context.Context, host string, port int, rootUser, rootPassword, knownHost string, spec sshx.UserSpec) (string, error) {
	return "", f.err
}
func (f *failExec) DeleteUser(ctx context.Context, host string, port int, rootUser, rootPassword, knownHost string, spec sshx.UserSpec) (string, error) {
	return "", f.err
}
func (f *failExec) UpdatePermissions(ctx context.Context, host string, port int, rootUser, rootPassword, knownHost string, spec sshx.UserSpec) (string, error) {
	return "", f.err
}
func (f *failExec) TestConnection(ctx context.Context, host string, port int, rootUser, rootPassword, knownHost string) (string, error) {
	return "", f.err
}
func (f *failExec) LockUser(ctx context.Context, host string, port int, rootUser, rootPassword, knownHost, username string) (string, error) {
	return "", f.err
}
func (f *failExec) ProbeMode(ctx context.Context, host string, port int, adminUser, adminPassword, knownHost string) (string, string, error) {
	return "", "", f.err
}
func (f *failExec) AttachVerify(ctx context.Context, host string, port int, username, password, knownHost string) (string, error) {
	return "", f.err
}
func (f *failExec) AttachSetPermissions(ctx context.Context, host string, port int, adminUser, adminPassword, knownHost string, granted, removed []sshx.PermissionSpec) (string, error) {
	return "", f.err
}
func (f *failExec) AttachLock(ctx context.Context, host string, port int, adminUser, adminPassword, knownHost string, revoked []sshx.PermissionSpec) (string, error) {
	return "", f.err
}

func TestCreateAccountProvision(t *testing.T) {
	srv := newTestServer(t)
	fx := &fakeExec{}
	srv.exec = fx
	h := srv.Handler()

	sv, _ := srv.st.CreateServer(context.Background(), "s1", "10.0.0.1", 22, "root", "rp")
	body := `{"username":"alice","password":"alicepw","coding_capable":true,"exposed_to_agent":true,"permissions":[{"path":"/data/a","mode":"rw"}]}`
	req := authedRequest(t, srv, h, "POST", "/api/servers/"+sv.ID+"/accounts", []byte(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body)
	}
	if fx.created != 1 {
		t.Fatalf("executor not called")
	}

	accs, _ := srv.st.ListAccounts(context.Background(), sv.ID)
	if len(accs) != 1 || accs[0].Status != store.StatusActive {
		t.Fatalf("acc=%+v", accs)
	}
}

func TestUpdateAccountFlags(t *testing.T) {
	srv := newTestServer(t)
	srv.exec = &fakeExec{}
	h := srv.Handler()
	sv, _ := srv.st.CreateServer(context.Background(), "s1", "10.0.0.1", 22, "root", "rp")

	body := `{"username":"alice","password":"pw","coding_capable":false,"exposed_to_agent":false,"permissions":[]}`
	req := authedRequest(t, srv, h, "POST", "/api/servers/"+sv.ID+"/accounts", []byte(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create code=%d body=%s", rec.Code, rec.Body)
	}
	var created accountDTO
	json.Unmarshal(rec.Body.Bytes(), &created)

	// 翻转两个标记，确认持久化且可通过 ListExposedAccounts 查到。
	req = authedRequest(t, srv, h, "PUT", "/api/accounts/"+created.ID, []byte(`{"coding_capable":true,"exposed_to_agent":true}`))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("update code=%d body=%s", rec.Code, rec.Body)
	}

	exposed, _ := srv.st.ListExposedAccounts(context.Background(), "9999-01-01T00:00:00Z")
	if len(exposed) != 1 || !exposed[0].CodingCapable {
		t.Fatalf("exposed=%+v", exposed)
	}
}

func TestProvisionFailureMarksError(t *testing.T) {
	srv := newTestServer(t)
	fx := &failExec{err: fmt.Errorf("boom")}
	srv.exec = fx
	h := srv.Handler()
	sv, _ := srv.st.CreateServer(context.Background(), "s1", "10.0.0.1", 22, "root", "rp")
	body := `{"username":"bob","password":"pw","permissions":[]}`
	req := authedRequest(t, srv, h, "POST", "/api/servers/"+sv.ID+"/accounts", []byte(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body)
	}
	accs, _ := srv.st.ListAccounts(context.Background(), sv.ID)
	if len(accs) != 1 || accs[0].Status != store.StatusError || accs[0].LastError == "" {
		t.Fatalf("acc=%+v", accs)
	}
}

func TestProvisionFailurePreservesFlags(t *testing.T) {
	srv := newTestServer(t)
	srv.exec = &failExec{err: fmt.Errorf("boom")}
	h := srv.Handler()
	sv, _ := srv.st.CreateServer(context.Background(), "s1", "10.0.0.1", 22, "root", "rp")
	body := `{"username":"alice","password":"pw","coding_capable":true,"exposed_to_agent":true,"permissions":[]}`
	req := authedRequest(t, srv, h, "POST", "/api/servers/"+sv.ID+"/accounts", []byte(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body)
	}
	accs, _ := srv.st.ListAccounts(context.Background(), sv.ID)
	// 建户失败仅标记 status=error，不得清空编码/暴露标志。
	if len(accs) != 1 || !accs[0].CodingCapable || !accs[0].ExposedToAgent || accs[0].Status != store.StatusError {
		t.Fatalf("flags lost: %+v", accs[0])
	}
}

// plain（attach-only）服务器：建「别的用户名」被拒绝；attach 管理账户本人走 AttachVerify + AttachSetPermissions；
// 删账户不删 OS 用户（只撤 ACL + 删记录）；改密码被拒绝。
func TestPlainModeAttach(t *testing.T) {
	srv := newTestServer(t)
	fx := &fakeExec{probed: store.AccessPlain}
	srv.exec = fx
	h := srv.Handler()
	sv, _ := srv.st.CreateServer(context.Background(), "shared", "10.0.0.9", 22, "dev", "devpw")
	sv.AccessMode = store.AccessPlain
	_ = srv.st.UpdateServer(context.Background(), *sv)

	// 1) attach 管理账户本人：应走 AttachVerify 路径
	body := `{"username":"dev","password":"devpw","coding_capable":true,"exposed_to_agent":true,"permissions":[{"path":"/home/dev/proj","mode":"rw"}]}`
	req := authedRequest(t, srv, h, "POST", "/api/servers/"+sv.ID+"/accounts", []byte(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("attach create code=%d body=%s", rec.Code, rec.Body)
	}
	if fx.attached != 1 || fx.attachSet != 1 {
		t.Fatalf("attach calls: verify=%d set=%d", fx.attached, fx.attachSet)
	}
	if fx.created != 0 {
		t.Fatal("plain mode must not call CreateUser")
	}
	var created accountDTO
	json.Unmarshal(rec.Body.Bytes(), &created)

	// 2) 建其他用户名 → 400
	req = authedRequest(t, srv, h, "POST", "/api/servers/"+sv.ID+"/accounts",
		[]byte(`{"username":"other","password":"x","permissions":[]}`))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("mismatched username code=%d body=%s", rec.Code, rec.Body)
	}

	// 3) 改密码 → 400
	req = authedRequest(t, srv, h, "PUT", "/api/accounts/"+created.ID+"/password", []byte(`{"password":"x"}`))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("plain change password code=%d", rec.Code)
	}

	// 4) 改权限 → AttachSetPermissions
	req = authedRequest(t, srv, h, "PUT", "/api/accounts/"+created.ID+"/permissions",
		[]byte(`[{"path":"/home/dev/proj2","mode":"ro"}]`))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("attach set perms code=%d body=%s", rec.Code, rec.Body)
	}
	if fx.attachSet != 2 {
		t.Fatalf("attachSet=%d want 2", fx.attachSet)
	}

	// 5) 删账户 → 不删 OS 用户，只撤 ACL 删记录
	req = authedRequest(t, srv, h, "DELETE", "/api/accounts/"+created.ID, nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("attach delete code=%d", rec.Code)
	}
	if fx.attachLk != 1 || fx.deleted != 0 {
		t.Fatalf("attach delete: lock=%d delete=%d", fx.attachLk, fx.deleted)
	}
	accs, _ := srv.st.ListAccounts(context.Background(), sv.ID)
	if len(accs) != 0 {
		t.Fatalf("record must be removed: %d", len(accs))
	}
}

func TestSetPermissionsPushesRevocation(t *testing.T) {
	srv := newTestServer(t)
	fx := &fakeExec{}
	srv.exec = fx
	h := srv.Handler()
	sv, _ := srv.st.CreateServer(context.Background(), "s1", "10.0.0.1", 22, "root", "rp")

	body := `{"username":"alice","password":"pw","permissions":[{"path":"/data/a","mode":"rw"}]}`
	req := authedRequest(t, srv, h, "POST", "/api/servers/"+sv.ID+"/accounts", []byte(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var created accountDTO
	json.Unmarshal(rec.Body.Bytes(), &created)

	// 改权限为仅 /data/b，应推送到服务器并撤销 /data/a。
	req = authedRequest(t, srv, h, "PUT", "/api/accounts/"+created.ID+"/permissions", []byte(`[{"path":"/data/b","mode":"ro"}]`))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("set perms code=%d body=%s", rec.Code, rec.Body)
	}
	if fx.updated == nil {
		t.Fatal("UpdatePermissions not called")
	}
	if len(fx.updated.Permissions) != 1 || fx.updated.Permissions[0].Path != "/data/b" {
		t.Fatalf("perms=%+v", fx.updated.Permissions)
	}
	if len(fx.updated.Removed) != 1 || fx.updated.Removed[0].Path != "/data/a" {
		t.Fatalf("removed=%+v", fx.updated.Removed)
	}
}

func TestDeleteAccountFailureKeepsRecord(t *testing.T) {
	srv := newTestServer(t)
	srv.exec = &failExec{err: fmt.Errorf("ssh down")}
	h := srv.Handler()
	sv, _ := srv.st.CreateServer(context.Background(), "s1", "10.0.0.1", 22, "root", "rp")

	body := `{"username":"alice","password":"pw","permissions":[]}`
	req := authedRequest(t, srv, h, "POST", "/api/servers/"+sv.ID+"/accounts", []byte(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var created accountDTO
	json.Unmarshal(rec.Body.Bytes(), &created)

	req = authedRequest(t, srv, h, "DELETE", "/api/accounts/"+created.ID, nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("delete code=%d body=%s", rec.Code, rec.Body)
	}
	// 远端删户失败则保留 DB 记录，避免孤儿账户。
	accs, _ := srv.st.ListAccounts(context.Background(), sv.ID)
	if len(accs) != 1 {
		t.Fatalf("account should be kept, got %d", len(accs))
	}
}

func TestListAccounts(t *testing.T) {
	srv := newTestServer(t)
	srv.exec = &fakeExec{}
	h := srv.Handler()

	sv, _ := srv.st.CreateServer(context.Background(), "s1", "10.0.0.1", 22, "root", "rp")
	body := `{"username":"alice","password":"pw","permissions":[{"path":"/data/a","mode":"rw"},{"path":"/data/b","mode":"ro"}]}`
	req := authedRequest(t, srv, h, "POST", "/api/servers/"+sv.ID+"/accounts", []byte(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	req = authedRequest(t, srv, h, "GET", "/api/servers/"+sv.ID+"/accounts", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list code=%d body=%s", rec.Code, rec.Body)
	}
	var out []accountDTO
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || len(out[0].Permissions) != 2 {
		t.Fatalf("out=%+v", out)
	}
	if out[0].Permissions[0].Path != "/data/a" || out[0].Permissions[1].Mode != "ro" {
		t.Fatalf("perms=%+v", out[0].Permissions)
	}
}

func TestChangePassword(t *testing.T) {
	srv := newTestServer(t)
	fx := &fakeExec{}
	srv.exec = fx
	h := srv.Handler()

	sv, _ := srv.st.CreateServer(context.Background(), "s1", "10.0.0.1", 22, "root", "rp")
	body := `{"username":"alice","password":"oldpw","permissions":[{"path":"/data/a","mode":"rw"}]}`
	req := authedRequest(t, srv, h, "POST", "/api/servers/"+sv.ID+"/accounts", []byte(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var created accountDTO
	json.Unmarshal(rec.Body.Bytes(), &created)

	req = authedRequest(t, srv, h, "PUT", "/api/accounts/"+created.ID+"/password", []byte(`{"password":"newpw"}`))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("change code=%d body=%s", rec.Code, rec.Body)
	}
	// 远端执行器应被调用（重置密码），且库中密码已更新。
	if fx.created == 0 {
		t.Fatal("executor not called for password reset")
	}
	a, _ := srv.st.GetAccount(context.Background(), created.ID)
	pw, err := srv.st.Decrypt(a.PasswordEnc)
	if err != nil || string(pw) != "newpw" {
		t.Fatalf("decrypted=%q err=%v", pw, err)
	}
	if a.Status != store.StatusActive {
		t.Fatalf("status=%q", a.Status)
	}
}

func TestChangePasswordFailureMarksError(t *testing.T) {
	srv := newTestServer(t)
	srv.exec = &fakeExec{} // 建户成功
	h := srv.Handler()

	sv, _ := srv.st.CreateServer(context.Background(), "s1", "10.0.0.1", 22, "root", "rp")
	body := `{"username":"alice","password":"oldpw","permissions":[]}`
	req := authedRequest(t, srv, h, "POST", "/api/servers/"+sv.ID+"/accounts", []byte(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var created accountDTO
	json.Unmarshal(rec.Body.Bytes(), &created)

	// 改密码时远端失败 → 502 且保留旧密码、标记 error。
	srv.exec = &failExec{err: fmt.Errorf("ssh down")}
	req = authedRequest(t, srv, h, "PUT", "/api/accounts/"+created.ID+"/password", []byte(`{"password":"newpw"}`))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("change code=%d body=%s", rec.Code, rec.Body)
	}
	a, _ := srv.st.GetAccount(context.Background(), created.ID)
	pw, _ := srv.st.Decrypt(a.PasswordEnc)
	if string(pw) != "oldpw" {
		t.Fatalf("password must be unchanged, got %q", pw)
	}
	if a.Status != store.StatusError {
		t.Fatalf("status=%q", a.Status)
	}
}

func TestDeleteAccountPersistsHostKey(t *testing.T) {
	srv := newTestServer(t)
	srv.exec = &failExec{err: fmt.Errorf("boom")} // 建户失败 → HostKey 保持空
	h := srv.Handler()
	sv, _ := srv.st.CreateServer(context.Background(), "s1", "10.0.0.1", 22, "root", "rp")

	body := `{"username":"alice","password":"pw","permissions":[]}`
	req := authedRequest(t, srv, h, "POST", "/api/servers/"+sv.ID+"/accounts", []byte(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var created accountDTO
	json.Unmarshal(rec.Body.Bytes(), &created)

	// 改用成功的 executor 删户，应把观察到的指纹回写（完成 TOFU 固定）。
	srv.exec = &fakeExec{}
	req = authedRequest(t, srv, h, "DELETE", "/api/accounts/"+created.ID, nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete code=%d body=%s", rec.Code, rec.Body)
	}
	got, _ := srv.st.GetServer(context.Background(), sv.ID)
	if got.HostKey != "fp" {
		t.Fatalf("host key not persisted after delete: %q", got.HostKey)
	}
}
