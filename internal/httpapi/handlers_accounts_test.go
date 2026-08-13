package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"serveragentlink/internal/sshx"
	"serveragentlink/internal/store"
)

type fakeExec struct{ created int }

func (f *fakeExec) CreateUser(ctx context.Context, host string, port int, rootUser, rootPassword, knownHost string, spec sshx.UserSpec) (string, error) {
	f.created++
	return "fp", nil
}
func (f *fakeExec) DeleteUser(ctx context.Context, host string, port int, rootUser, rootPassword string, spec sshx.UserSpec) error {
	return nil
}
func (f *fakeExec) UpdatePermissions(ctx context.Context, host string, port int, rootUser, rootPassword string, spec sshx.UserSpec) error {
	return nil
}

type failExec struct{ err error }

func (f *failExec) CreateUser(ctx context.Context, host string, port int, rootUser, rootPassword, knownHost string, spec sshx.UserSpec) (string, error) {
	return "", f.err
}
func (f *failExec) DeleteUser(ctx context.Context, host string, port int, rootUser, rootPassword string, spec sshx.UserSpec) error {
	return nil
}
func (f *failExec) UpdatePermissions(ctx context.Context, host string, port int, rootUser, rootPassword string, spec sshx.UserSpec) error {
	return nil
}

func TestCreateAccountProvision(t *testing.T) {
	srv := newTestServer(t)
	fx := &fakeExec{}
	srv.exec = fx
	h := srv.Handler()
	cookie := login(t, srv, h)

	sv, _ := srv.st.CreateServer(context.Background(), "s1", "10.0.0.1", 22, "root", "rp")
	body := `{"username":"alice","password":"alicepw","coding_capable":true,"exposed_to_agent":true,"permissions":[{"path":"/data/a","mode":"rw"}]}`
	req := httptest.NewRequest("POST", "/api/servers/"+sv.ID+"/accounts", bytes.NewReader([]byte(body)))
	req.AddCookie(cookie)
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
	cookie := login(t, srv, h)
	sv, _ := srv.st.CreateServer(context.Background(), "s1", "10.0.0.1", 22, "root", "rp")

	body := `{"username":"alice","password":"pw","coding_capable":false,"exposed_to_agent":false,"permissions":[]}`
	req := httptest.NewRequest("POST", "/api/servers/"+sv.ID+"/accounts", bytes.NewReader([]byte(body)))
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create code=%d body=%s", rec.Code, rec.Body)
	}
	var created accountDTO
	json.Unmarshal(rec.Body.Bytes(), &created)

	// 翻转两个标记，确认持久化且可通过 ListExposedAccounts 查到。
	req = httptest.NewRequest("PUT", "/api/accounts/"+created.ID, bytes.NewReader([]byte(`{"coding_capable":true,"exposed_to_agent":true}`)))
	req.AddCookie(cookie)
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
	cookie := login(t, srv, h)
	sv, _ := srv.st.CreateServer(context.Background(), "s1", "10.0.0.1", 22, "root", "rp")
	body := `{"username":"bob","password":"pw","permissions":[]}`
	req := httptest.NewRequest("POST", "/api/servers/"+sv.ID+"/accounts", bytes.NewReader([]byte(body)))
	req.AddCookie(cookie)
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
