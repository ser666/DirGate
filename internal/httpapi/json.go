package httpapi

import (
	"encoding/json"
	"log"
	"net/http"
)

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

// writeNoContent 写 204 且不带 body/Content-Type（符合 RFC 9110 对 204 的要求）。
func writeNoContent(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNoContent)
}

// writeErr 返回脱敏的通用错误给客户端，同时把原始错误与服务端上下文写入日志——
// 客户端不承担排障职责，真正的根因只在服务端日志里。
func writeErr(w http.ResponseWriter, r *http.Request, code int, msg string, err error) {
	if err != nil {
		log.Printf("%s %s: %s: %v", r.Method, r.URL.Path, msg, err)
	}
	writeJSON(w, code, map[string]string{"error": msg})
}

// logRemoteErr 记录远端 SSH 执行失败（错误详情会回传给调用方，但仍留服务端日志一份）。
func logRemoteErr(r *http.Request, what string, err error) {
	log.Printf("%s %s: %s: %v", r.Method, r.URL.Path, what, err)
}

// audit 记录一次管理操作（谁、何时、对什么对象、做了什么），写 stdout 供 systemd/journald 收集。
func (s *Server) audit(r *http.Request, action, object string) {
	log.Printf("audit user=%s ip=%s action=%s object=%s", s.adminUser, clientIP(r), action, object)
}
