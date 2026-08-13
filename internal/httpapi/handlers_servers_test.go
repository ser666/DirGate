package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
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
	_, _ = srv.st.CreateAccount(context.Background(), sv.ID, "alice", "pw", true, true)
	_, _ = srv.st.CreateAccount(context.Background(), sv.ID, "bob", "pw", false, false)

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
	_, _ = srv.st.CreateAccount(context.Background(), sv.ID, "alice", "pw", true, true)

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
