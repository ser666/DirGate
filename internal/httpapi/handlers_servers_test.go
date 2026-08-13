package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCreateAndListServers(t *testing.T) {
	srv := newTestServer(t)
	h := srv.Handler()
	cookie := login(t, srv, h)

	body := `{"name":"dev1","host":"10.0.0.5","ssh_port":22,"root_user":"root","root_password":"rootpw"}`
	req := httptest.NewRequest("POST", "/api/servers", bytes.NewReader([]byte(body)))
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create code=%d body=%s", rec.Code, rec.Body)
	}

	req = httptest.NewRequest("GET", "/api/servers", nil)
	req.AddCookie(cookie)
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
	cookie := login(t, srv, h)

	body := `{"name":"dev1","host":"10.0.0.5","ssh_port":22,"root_user":"root","root_password":"rootpw"}`
	req := httptest.NewRequest("POST", "/api/servers", bytes.NewReader([]byte(body)))
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var created map[string]any
	json.Unmarshal(rec.Body.Bytes(), &created)

	req = httptest.NewRequest("DELETE", "/api/servers/"+created["id"].(string), nil)
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete code=%d", rec.Code)
	}
}
