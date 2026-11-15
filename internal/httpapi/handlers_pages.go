package httpapi

import (
	"net/http"
	"time"

	"serveragentlink/internal/store"
)

type serverView struct {
	store.Server
	AccountCount int
	Verified     bool
}

type accountView struct {
	store.Account
	Permissions []store.DirectoryPermission
}

type exposedAccountView struct {
	ServerID    string
	ServerName  string
	Host        string
	SSHPort     int
	Username    string
	Directories []store.DirectoryPermission
}

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, "login", map[string]any{"Authed": false})
}

func (s *Server) handleServersPage(w http.ResponseWriter, r *http.Request) {
	servers, err := s.st.ListServers(r.Context())
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "db error", err)
		return
	}
	views := make([]serverView, 0, len(servers))
	for _, sv := range servers {
		accounts, err := s.st.ListAccounts(r.Context(), sv.ID)
		if err != nil {
			writeErr(w, r, http.StatusInternalServerError, "db error", err)
			return
		}
		views = append(views, serverView{
			Server:       sv,
			AccountCount: len(accounts),
			Verified:     sv.HostKey != "",
		})
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	exposed, err := s.st.ListExposedAccounts(r.Context(), now)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "db error", err)
		return
	}
	expViews := make([]exposedAccountView, 0, len(exposed))
	for _, e := range exposed {
		expViews = append(expViews, exposedAccountView{
			ServerID:    e.ServerID,
			ServerName:  e.ServerName,
			Host:        e.Host,
			SSHPort:     e.SSHPort,
			Username:    e.Username,
			Directories: e.Directories,
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
	accounts, err := s.st.ListAccounts(r.Context(), sv.ID)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "db error", err)
		return
	}
	views := make([]accountView, 0, len(accounts))
	for _, a := range accounts {
		perms, err := s.st.ListPermissions(r.Context(), a.ID)
		if err != nil {
			writeErr(w, r, http.StatusInternalServerError, "db error", err)
			return
		}
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
