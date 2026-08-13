package httpapi

import (
	"context"
	"net/http"

	"serveragentlink/internal/sshx"
	"serveragentlink/internal/store"
)

// userExecutor 是 sshx.Executor 的可注入接口，便于测试用 fake 替身。
type userExecutor interface {
	CreateUser(ctx context.Context, host string, port int, rootUser, rootPassword, knownHost string, spec sshx.UserSpec) (string, error)
	DeleteUser(ctx context.Context, host string, port int, rootUser, rootPassword string, spec sshx.UserSpec) error
	UpdatePermissions(ctx context.Context, host string, port int, rootUser, rootPassword string, spec sshx.UserSpec) error
}

type Server struct {
	st         *store.Store
	key        []byte
	adminUser  string
	exec       userExecutor
	mcpHandler http.Handler
	backend    string
}

func New(st *store.Store, key []byte, adminUser string, exec userExecutor, mcpHandler http.Handler, backend string) *Server {
	return &Server{st: st, key: key, adminUser: adminUser, exec: exec, mcpHandler: mcpHandler, backend: backend}
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
	api.HandleFunc("POST /api/servers/{id}/accounts", s.handleCreateAccount)
	api.HandleFunc("POST /api/accounts/{id}/provision", s.handleProvisionAccount)
	api.HandleFunc("DELETE /api/accounts/{id}", s.handleDeleteAccount)
	api.HandleFunc("GET /api/accounts/{id}/permissions", s.handleListPermissions)
	api.HandleFunc("PUT /api/accounts/{id}/permissions", s.handleSetPermissions)

	mux.Handle("/api/", s.requireAuth(api))

	if s.mcpHandler != nil {
		mux.Handle("/mcp", s.mcpHandler)
	}
	return mux
}
