package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"dirgate/internal/store"
)

func TestCreateAndListServers(t *testing.T) {
	srv := newTestServer(t)
	h := srv.Handler()

	body := `{"name":"dev1","host":"10.0.0.5","ssh_port":22,"root_user":"root","root_password":"rootpw"}`
	req := authedRequest(t, srv, h, "POST", "/api/servers", []byte(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create code=%d body=%s", rec.Code, rec.Body)
	}

	req = authedRequest(t, srv, h, "GET", "/api/servers", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list code=%d", rec.Code)
	}
	var list []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0]["host"] != "10.0.0.5" {
		t.Fatalf("list=%+v", list)
	}
	// 响应中不暴露密文
	for _, k := range []string{"root_password", "root_password_enc"} {
		if _, ok := list[0][k]; ok {
			t.Fatalf("must not expose %s in JSON", k)
		}
	}
}

func TestDeleteServer(t *testing.T) {
	srv := newTestServer(t)
	h := srv.Handler()

	body := `{"name":"dev1","host":"10.0.0.5","ssh_port":22,"root_user":"root","root_password":"rootpw"}`
	req := authedRequest(t, srv, h, "POST", "/api/servers", []byte(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var created map[string]any
	json.Unmarshal(rec.Body.Bytes(), &created)

	req = authedRequest(t, srv, h, "DELETE", "/api/servers/"+created["id"].(string), nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete code=%d body=%s", rec.Code, rec.Body)
	}
}

func TestUpdateServerClearsHostKeyOnHostChange(t *testing.T) {
	srv := newTestServer(t)
	srv.exec = &fakeExec{}
	h := srv.Handler()

	sv, _ := srv.st.CreateServer(context.Background(), "dev1", "10.0.0.5", 22, "root", "rootpw")
	sv.HostKey = "SHA256:oldfp"
	_ = srv.st.UpdateServer(context.Background(), *sv)

	req := authedRequest(t, srv, h, "PUT", "/api/servers/"+sv.ID, []byte(`{"host":"10.0.0.6"}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body)
	}
	got, _ := srv.st.GetServer(context.Background(), sv.ID)
	if got.Host != "10.0.0.6" || got.HostKey != "" {
		t.Fatalf("host=%q host_key=%q (want cleared)", got.Host, got.HostKey)
	}
}

func TestUpdateServerResetHostKey(t *testing.T) {
	srv := newTestServer(t)
	srv.exec = &fakeExec{}
	h := srv.Handler()

	sv, _ := srv.st.CreateServer(context.Background(), "dev1", "10.0.0.5", 22, "root", "rootpw")
	sv.HostKey = "SHA256:oldfp"
	_ = srv.st.UpdateServer(context.Background(), *sv)

	req := authedRequest(t, srv, h, "PUT", "/api/servers/"+sv.ID, []byte(`{"reset_host_key":true}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body)
	}
	got, _ := srv.st.GetServer(context.Background(), sv.ID)
	if got.HostKey != "" {
		t.Fatalf("host_key should be reset, got %q", got.HostKey)
	}
}

func TestDeleteServerCleansUpRemoteUsers(t *testing.T) {
	srv := newTestServer(t)
	fx := &fakeExec{}
	srv.exec = fx
	h := srv.Handler()

	sv, _ := srv.st.CreateServer(context.Background(), "dev1", "10.0.0.5", 22, "root", "rootpw")
	_, _ = srv.st.CreateAccount(context.Background(), sv.ID, "alice", "pw", true)
	_, _ = srv.st.CreateAccount(context.Background(), sv.ID, "bob", "pw", false)

	req := authedRequest(t, srv, h, "DELETE", "/api/servers/"+sv.ID, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete code=%d body=%s", rec.Code, rec.Body)
	}
	if fx.deleted != 2 {
		t.Fatalf("expected 2 remote deletes, got %d", fx.deleted)
	}
}

func TestDeleteServerRemoteFailureKeepsRecord(t *testing.T) {
	srv := newTestServer(t)
	srv.exec = &failExec{err: context.DeadlineExceeded}
	h := srv.Handler()

	sv, _ := srv.st.CreateServer(context.Background(), "dev1", "10.0.0.5", 22, "root", "rootpw")
	_, _ = srv.st.CreateAccount(context.Background(), sv.ID, "alice", "pw", true)

	req := authedRequest(t, srv, h, "DELETE", "/api/servers/"+sv.ID, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("delete code=%d body=%s", rec.Code, rec.Body)
	}
	if _, err := srv.st.GetServer(context.Background(), sv.ID); err != nil {
		t.Fatalf("server should be kept: %v", err)
	}
}

func TestServerDetailPageRendersAccountsAndPerms(t *testing.T) {
	srv := newTestServer(t)
	h := srv.Handler()

	sv, _ := srv.st.CreateServer(context.Background(), "dev1", "10.0.0.5", 22, "root", "rootpw")
	a, _ := srv.st.CreateAccount(context.Background(), sv.ID, "alice", "pw", true)
	_ = srv.st.SetPermissions(context.Background(), a.ID, []store.DirectoryPermission{{Path: "/data/repo", Mode: store.ModeReadWrite}})

	session := login(t, srv, h)
	req := httptest.NewRequest("GET", "/servers/"+sv.ID, nil)
	req.AddCookie(session)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"alice", "/data/repo", "rw", "返回服务器列表", "改权限", "改密码"} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q in rendered page:\n%s", want, body)
		}
	}
}

func TestServersPageListsExposedAccounts(t *testing.T) {
	srv := newTestServer(t)
	h := srv.Handler()

	sv, _ := srv.st.CreateServer(context.Background(), "dev1", "10.0.0.5", 22, "root", "rootpw")
	a, _ := srv.st.CreateAccount(context.Background(), sv.ID, "coder1", "pw", true)
	_ = srv.st.SetPermissions(context.Background(), a.ID, []store.DirectoryPermission{{Path: "/data/repo", Mode: store.ModeReadWrite}})
	// 未暴露的账户不应出现在首页概览里。
	_, _ = srv.st.CreateAccount(context.Background(), sv.ID, "hidden", "pw", false)

	session := login(t, srv, h)
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(session)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"已暴露给 agent 的账户", "coder1", "dev1", "10.0.0.5", "/data/repo", "rw"} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q in rendered homepage:\n%s", want, body)
		}
	}
	if strings.Contains(body, "hidden") {
		t.Fatalf("non-exposed account must not appear in exposed overview:\n%s", body)
	}
}

func TestTestServerConnectionSuccess(t *testing.T) {
	srv := newTestServer(t)
	srv.exec = &fakeExec{}
	h := srv.Handler()

	sv, _ := srv.st.CreateServer(context.Background(), "dev1", "10.0.0.5", 22, "root", "rootpw")

	req := authedRequest(t, srv, h, "POST", "/api/servers/"+sv.ID+"/test", []byte(`{}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body)
	}
	var out struct {
		Connected bool   `json:"connected"`
		HostKey   string `json:"host_key"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || !out.Connected || out.HostKey != "fp" {
		t.Fatalf("out=%+v err=%v", out, err)
	}
	got, _ := srv.st.GetServer(context.Background(), sv.ID)
	if got.HostKey != "fp" {
		t.Fatalf("host key not persisted: %q", got.HostKey)
	}
	if got.LastVerifiedAt == "" {
		t.Fatal("last_verified_at should be set")
	}
}

func TestTestServerConnectionFailure(t *testing.T) {
	srv := newTestServer(t)
	srv.exec = &failExec{err: fmt.Errorf("dial tcp: connection refused")}
	h := srv.Handler()

	sv, _ := srv.st.CreateServer(context.Background(), "dev1", "10.0.0.5", 22, "root", "rootpw")

	req := authedRequest(t, srv, h, "POST", "/api/servers/"+sv.ID+"/test", []byte(`{}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body)
	}
	var out struct {
		Connected bool   `json:"connected"`
		Error     string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.Connected {
		t.Fatalf("out=%+v err=%v", out, err)
	}
	got, _ := srv.st.GetServer(context.Background(), sv.ID)
	if got.HostKey != "" || got.LastVerifiedAt != "" {
		t.Fatalf("failure must not persist: host_key=%q verified_at=%q", got.HostKey, got.LastVerifiedAt)
	}
}
