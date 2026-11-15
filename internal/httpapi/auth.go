package httpapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"dirgate/internal/crypto"
)

const (
	sessionCookie = "sal_session"
	csrfCookie    = "sal_csrf"
)

func (s *Server) mac(msg string) string {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte(msg))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (s *Server) signCookie(payload string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + s.mac(payload)
}

func (s *Server) verifyCookie(cookie string) (string, bool) {
	parts := strings.Split(cookie, ".")
	if len(parts) != 2 {
		return "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", false
	}
	payload := string(raw)
	if !hmac.Equal([]byte(s.mac(payload)), []byte(parts[1])) {
		return "", false
	}
	return payload, true
}

type sessionPayload struct {
	User string `json:"u"`
	Exp  int64  `json:"e"`
}

// requireAuth 保护 /api/* 除 /api/login 与 /api/logout 外的所有路由。
// 对状态变更方法额外校验 CSRF token（double-submit：header 与 cookie 一致）。
func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil {
			writeErr(w, r, http.StatusUnauthorized, "unauthorized", nil)
			return
		}
		payload, ok := s.verifyCookie(c.Value)
		if !ok {
			writeErr(w, r, http.StatusUnauthorized, "unauthorized", nil)
			return
		}
		var sp sessionPayload
		if json.Unmarshal([]byte(payload), &sp) != nil || sp.User != s.adminUser || sp.Exp < time.Now().Unix() {
			writeErr(w, r, http.StatusUnauthorized, "unauthorized", nil)
			return
		}
		if isStateChanging(r.Method) && !s.csrfValid(r) {
			writeErr(w, r, http.StatusForbidden, "invalid csrf token", nil)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isStateChanging(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch:
		return true
	}
	return false
}

// csrfValid 用 double-submit cookie 校验 CSRF：请求头 X-CSRF-Token 必须与 sal_csrf cookie 一致。
// 攻击者（即便同站子域）无法读取本站的 host-only cookie，因此无法伪造该头。
func (s *Server) csrfValid(r *http.Request) bool {
	c, err := r.Cookie(csrfCookie)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(c.Value)) == 1
}

// 登录限流：原子地「检查并记录」，消除 check 与 record 之间的 TOCTOU 窗口；
// 同时每次访问修剪全表过期条目，避免 map 因轮换源 IP 而无限增长。
var loginAttempts = struct {
	sync.Mutex
	m map[string][]time.Time
}{m: map[string][]time.Time{}}

const maxLoginAttempts = 5

func reserveLoginAttempt(ip string) bool {
	loginAttempts.Lock()
	defer loginAttempts.Unlock()
	now := time.Now()
	cut := now.Add(-time.Minute)
	for k, ts := range loginAttempts.m {
		kept := ts[:0]
		for _, t := range ts {
			if t.After(cut) {
				kept = append(kept, t)
			}
		}
		if len(kept) == 0 {
			delete(loginAttempts.m, k)
		} else {
			loginAttempts.m[k] = kept
		}
	}
	if len(loginAttempts.m[ip]) >= maxLoginAttempts {
		return false
	}
	loginAttempts.m[ip] = append(loginAttempts.m[ip], now)
	return true
}

// releaseLoginAttempt 在登录成功后撤销一次计数（成功登录不应累计进失败上限）。
func releaseLoginAttempt(ip string) {
	loginAttempts.Lock()
	defer loginAttempts.Unlock()
	if n := len(loginAttempts.m[ip]); n > 0 {
		loginAttempts.m[ip] = loginAttempts.m[ip][:n-1]
	}
}

func clientIP(r *http.Request) string {
	// 不信任客户端可伪造的 X-Forwarded-For（否则登录限流可被绕过）。
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !reserveLoginAttempt(ip) {
		writeErr(w, r, http.StatusTooManyRequests, "too many attempts", nil)
		return
	}
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil || in.Username != s.adminUser {
		writeErr(w, r, http.StatusUnauthorized, "invalid credentials", nil)
		return
	}
	admin, err := s.st.GetAdmin(r.Context())
	if err != nil || !crypto.VerifyPassword(admin.PasswordHash, in.Password) {
		writeErr(w, r, http.StatusUnauthorized, "invalid credentials", nil)
		return
	}
	releaseLoginAttempt(ip)

	payload, _ := json.Marshal(sessionPayload{User: s.adminUser, Exp: time.Now().Add(24 * time.Hour).Unix()})
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: s.signCookie(string(payload)),
		Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: s.secureCookies})

	csrfTok, _ := crypto.RandomToken()
	http.SetCookie(w, &http.Cookie{Name: csrfCookie, Value: csrfTok,
		Path: "/", SameSite: http.SameSiteStrictMode, Secure: s.secureCookies})
	writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: csrfCookie, Value: "", Path: "/", MaxAge: -1})
	writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
}
