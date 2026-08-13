package httpapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"serveragentlink/internal/crypto"
)

const sessionCookie = "sal_session"

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
	if s.mac(payload) != parts[1] {
		return "", false
	}
	return payload, true
}

type sessionPayload struct {
	User string `json:"u"`
	Exp  int64  `json:"e"`
}

// requireAuth 保护 /api/* 除 /api/login 外的所有路由。
func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		payload, ok := s.verifyCookie(c.Value)
		if !ok {
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		var sp sessionPayload
		if json.Unmarshal([]byte(payload), &sp) != nil || sp.User != s.adminUser || sp.Exp < time.Now().Unix() {
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next.ServeHTTP(w, r)
	})
}

var loginAttempts = struct {
	sync.Mutex
	m map[string][]time.Time
}{m: map[string][]time.Time{}}

func allowLogin(ip string) bool {
	loginAttempts.Lock()
	defer loginAttempts.Unlock()
	now := time.Now()
	cut := now.Add(-time.Minute)
	var kept []time.Time
	for _, t := range loginAttempts.m[ip] {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	loginAttempts.m[ip] = kept
	return len(kept) < 5
}

func recordLoginAttempt(ip string) {
	loginAttempts.Lock()
	defer loginAttempts.Unlock()
	loginAttempts.m[ip] = append(loginAttempts.m[ip], time.Now())
}

func clientIP(r *http.Request) string {
	if h := r.Header.Get("X-Forwarded-For"); h != "" {
		return strings.TrimSpace(strings.Split(h, ",")[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !allowLogin(ip) {
		writeErr(w, http.StatusTooManyRequests, "too many attempts")
		return
	}
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil || in.Username != s.adminUser {
		recordLoginAttempt(ip)
		writeErr(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	admin, err := s.st.GetAdmin(r.Context())
	if err != nil || !crypto.VerifyPassword(admin.PasswordHash, in.Password) {
		recordLoginAttempt(ip)
		writeErr(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	payload, _ := json.Marshal(sessionPayload{User: s.adminUser, Exp: time.Now().Add(24 * time.Hour).Unix()})
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: s.signCookie(string(payload)),
		Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
	writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1})
	writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
}
