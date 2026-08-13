package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"serveragentlink/internal/crypto"
	"serveragentlink/internal/store"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	key := make([]byte, 32)
	st, err := store.Open(t.TempDir(), key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	hash, _ := crypto.HashPassword("adminpw")
	_ = st.UpsertAdmin(context.Background(), "admin", hash)
	return New(st, key, "admin", nil, nil, "acl")
}

func login(t *testing.T, srv *Server, h http.Handler) *http.Cookie {
	t.Helper()
	req := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"admin","password":"adminpw"}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie {
			return c
		}
	}
	t.Fatal("no session cookie")
	return nil
}

func TestLoginSetsSessionAndRequiresAuth(t *testing.T) {
	srv := newTestServer(t)
	h := srv.Handler()

	// 未登录访问受保护路由 → 401
	req := httptest.NewRequest("GET", "/api/servers", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code=%d", rec.Code)
	}

	// 登录成功 → 200 + 设置 cookie
	body := `{"username":"admin","password":"adminpw"}`
	req = httptest.NewRequest("POST", "/api/login", strings.NewReader(body))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("login code=%d body=%s", rec.Code, rec.Body)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("no session cookie set")
	}
}

func TestLoginWrongPassword(t *testing.T) {
	srv := newTestServer(t)
	h := srv.Handler()
	req := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"admin","password":"nope"}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code=%d", rec.Code)
	}
}
