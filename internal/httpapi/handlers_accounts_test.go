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
	created int
	updated *sshx.UserSpec
	deleted int
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

	exposed, _ := srv.st.ListExposedAccounts(context.Background())
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
