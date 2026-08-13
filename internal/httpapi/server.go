package httpapi

import (
	"context"
	"html/template"
	"net/http"

	"serveragentlink/internal/sshx"
	"serveragentlink/internal/store"
	"serveragentlink/internal/web"
)

// userExecutor 是 sshx.Executor 的可注入接口，便于测试用 fake 替身。
type userExecutor interface {
	CreateUser(ctx context.Context, host string, port int, rootUser, rootPassword, knownHost string, spec sshx.UserSpec) (string, error)
	DeleteUser(ctx context.Context, host string, port int, rootUser, rootPassword, knownHost string, spec sshx.UserSpec) (string, error)
	UpdatePermissions(ctx context.Context, host string, port int, rootUser, rootPassword, knownHost string, spec sshx.UserSpec) (string, error)
	TestConnection(ctx context.Context, host string, port int, rootUser, rootPassword, knownHost string) (string, error)
}

type Server struct {
	st            *store.Store
	key           []byte
	adminUser     string
	exec          userExecutor
	mcpHandler    http.Handler
	secureCookies bool
	templates     *template.Template
}

func New(st *store.Store, key []byte, adminUser string, exec userExecutor, mcpHandler http.Handler, secureCookies bool) *Server {
	tmpl, err := web.ParseTemplates()
	if err != nil {
		panic(err) // 内嵌模板固定有效，Task 13 已测试可解析可执行
	}
	return &Server{st: st, key: key, adminUser: adminUser, exec: exec, mcpHandler: mcpHandler, secureCookies: secureCookies, templates: tmpl}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/logout", s.handleLogout)

	api := http.NewServeMux()
	api.HandleFunc("GET /api/servers", s.handleListServers)
	api.HandleFunc("POST /api/servers", s.handleCreateServer)
	api.HandleFunc("GET /api/servers/{id}", s.handleGetServer)
	api.HandleFunc("PUT /api/servers/{id}", s.handleUpdateServer)
	api.HandleFunc("DELETE /api/servers/{id}", s.handleDeleteServer)
	api.HandleFunc("GET /api/servers/{id}/accounts", s.handleListAccounts)
	api.HandleFunc("POST /api/servers/{id}/accounts", s.handleCreateAccount)
	api.HandleFunc("POST /api/servers/{id}/test", s.handleTestServer)
	api.HandleFunc("POST /api/accounts/{id}/provision", s.handleProvisionAccount)
	api.HandleFunc("PUT /api/accounts/{id}", s.handleUpdateAccount)
	api.HandleFunc("PUT /api/accounts/{id}/password", s.handleChangePassword)
	api.HandleFunc("DELETE /api/accounts/{id}", s.handleDeleteAccount)
	api.HandleFunc("GET /api/accounts/{id}/permissions", s.handleListPermissions)
	api.HandleFunc("PUT /api/accounts/{id}/permissions", s.handleSetPermissions)

	mux.Handle("/api/", s.requireAuth(api))

	if s.mcpHandler != nil {
		mux.Handle("/mcp", s.mcpHandler)
	}

	mux.Handle("GET /static/", http.FileServer(http.FS(web.FS)))
	mux.HandleFunc("GET /login", s.handleLoginPage)
	mux.Handle("GET /{$}", s.requireAuth(http.HandlerFunc(s.handleServersPage)))
	mux.Handle("GET /servers/{id}", s.requireAuth(http.HandlerFunc(s.handleServerPage)))
	return mux
}
