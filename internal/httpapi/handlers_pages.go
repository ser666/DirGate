package httpapi

import (
	"net/http"
	"strings"

	"serveragentlink/internal/store"
)

// serverView 是服务器列表页的行视图，附带账户数与验证状态。
type serverView struct {
	store.Server
	AccountCount int
	Verified     bool
}

// accountView 是账户行视图，附带目录权限清单（供详情页直接渲染）。
type accountView struct {
	store.Account
	Permissions []store.DirectoryPermission
}

// PermSpec 把权限渲染为「/path=mode,/path=mode」的紧凑字符串，用于表格展示与「改权限」输入框回填。
func (a accountView) PermSpec() string {
	parts := make([]string, 0, len(a.Permissions))
	for _, p := range a.Permissions {
		parts = append(parts, p.Path+"="+p.Mode)
	}
	return strings.Join(parts, ",")
}

// exposedAccountView 是首页「已暴露给 agent」概览的行视图，只含展示字段，不含凭据密文。
type exposedAccountView struct {
	ServerID      string
	ServerName    string
	Host          string
	SSHPort       int
	Username      string
	CodingCapable bool
	Directories   []store.DirectoryPermission
}

// DirSpec 把目录权限渲染为紧凑串，用于首页概览表格展示。
func (e exposedAccountView) DirSpec() string {
	parts := make([]string, 0, len(e.Directories))
	for _, p := range e.Directories {
		parts = append(parts, p.Path+"="+p.Mode)
	}
	return strings.Join(parts, ",")
}

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, "login", map[string]any{"Authed": false})
}

func (s *Server) handleServersPage(w http.ResponseWriter, r *http.Request) {
	servers, _ := s.st.ListServers(r.Context())
	views := make([]serverView, 0, len(servers))
	for _, sv := range servers {
		accounts, _ := s.st.ListAccounts(r.Context(), sv.ID)
		views = append(views, serverView{
			Server:       sv,
			AccountCount: len(accounts),
			Verified:     sv.HostKey != "",
		})
	}
	exposed, _ := s.st.ListExposedAccounts(r.Context())
	expViews := make([]exposedAccountView, 0, len(exposed))
	for _, e := range exposed {
		expViews = append(expViews, exposedAccountView{
			ServerID:      e.ServerID,
			ServerName:    e.ServerName,
			Host:          e.Host,
			SSHPort:       e.SSHPort,
			Username:      e.Username,
			CodingCapable: e.CodingCapable,
			Directories:   e.Directories,
		})
	}
	s.render(w, "servers", map[string]any{"Authed": true, "Servers": views, "Exposed": expViews})
}

func (s *Server) handleServerPage(w http.ResponseWriter, r *http.Request) {
	sv, err := s.st.GetServer(r.Context(), r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	accounts, _ := s.st.ListAccounts(r.Context(), sv.ID)
	views := make([]accountView, 0, len(accounts))
	for _, a := range accounts {
		perms, _ := s.st.ListPermissions(r.Context(), a.ID)
		views = append(views, accountView{Account: a, Permissions: perms})
	}
	s.render(w, "server_detail", map[string]any{
		"Authed":   true,
		"Server":   sv,
		"Verified": sv.HostKey != "",
		"Accounts": views,
	})
}

func (s *Server) render(w http.ResponseWriter, name string, data map[string]any) {
	if err := s.templates.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
