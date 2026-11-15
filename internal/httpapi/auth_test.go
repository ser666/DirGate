package httpapi

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"dirgate/internal/crypto"
	"dirgate/internal/store"
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
	return New(st, key, "admin", nil, nil, false)
}

// loginCookies 执行登录并返回 session 与 csrf 两个 cookie。
func loginCookies(t *testing.T, srv *Server, h http.Handler) (session, csrf *http.Cookie) {
	t.Helper()
	req := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"admin","password":"adminpw"}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	for _, c := range rec.Result().Cookies() {
		switch c.Name {
		case sessionCookie:
			session = c
		case csrfCookie:
			csrf = c
		}
	}
	if session == nil || csrf == nil {
		t.Fatalf("missing login cookies (session=%v csrf=%v)", session != nil, csrf != nil)
	}
	return session, csrf
}

func login(t *testing.T, srv *Server, h http.Handler) *http.Cookie {
	t.Helper()
	session, _ := loginCookies(t, srv, h)
	return session
}

// authedRequest 构造已登录（含 CSRF）的请求，供状态变更接口测试使用。
func authedRequest(t *testing.T, srv *Server, h http.Handler, method, url string, body []byte) *http.Request {
	t.Helper()
	session, csrf := loginCookies(t, srv, h)
	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, url, bytes.NewReader(body))
	} else {
		req = httptest.NewRequest(method, url, nil)
	}
	req.AddCookie(session)
	req.AddCookie(csrf)
	req.Header.Set("X-CSRF-Token", csrf.Value)
	return req
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

	// 登录成功 → 200 + 设置 session 与 csrf cookie
	body := `{"username":"admin","password":"adminpw"}`
	req = httptest.NewRequest("POST", "/api/login", strings.NewReader(body))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("login code=%d body=%s", rec.Code, rec.Body)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) < 2 {
		t.Fatalf("expected session + csrf cookies, got %d", len(cookies))
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

func TestStateChangingRequiresCSRF(t *testing.T) {
	srv := newTestServer(t)
	srv.exec = &fakeExec{}
	h := srv.Handler()
	session, csrf := loginCookies(t, srv, h)

	body := `{"name":"dev1","host":"10.0.0.5","root_password":"rootpw"}`

	// 只有 session、无 CSRF 头 → 403
	req := httptest.NewRequest("POST", "/api/servers", strings.NewReader(body))
	req.AddCookie(session)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body)
	}

	// 带 CSRF cookie + 头 → 201
	req = httptest.NewRequest("POST", "/api/servers", strings.NewReader(body))
	req.AddCookie(session)
	req.AddCookie(csrf)
	req.Header.Set("X-CSRF-Token", csrf.Value)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body)
	}
}

func TestReserveLoginAttemptLimits(t *testing.T) {
	loginAttempts.Lock()
	loginAttempts.m = map[string][]time.Time{}
	loginAttempts.Unlock()

	for i := 0; i < maxLoginAttempts; i++ {
		if !reserveLoginAttempt("1.2.3.4") {
			t.Fatalf("attempt %d should be allowed", i)
		}
	}
	if reserveLoginAttempt("1.2.3.4") {
		t.Fatal("6th attempt should be blocked")
	}
	releaseLoginAttempt("1.2.3.4")
	if !reserveLoginAttempt("1.2.3.4") {
		t.Fatal("after release, an attempt should be allowed again")
	}
}
