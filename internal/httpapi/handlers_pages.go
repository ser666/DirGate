package httpapi

import "net/http"

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, "login", map[string]any{"Authed": false})
}

func (s *Server) handleServersPage(w http.ResponseWriter, r *http.Request) {
	servers, _ := s.st.ListServers(r.Context())
	s.render(w, "servers", map[string]any{"Authed": true, "Servers": servers})
}

func (s *Server) handleServerPage(w http.ResponseWriter, r *http.Request) {
	sv, err := s.st.GetServer(r.Context(), r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	accounts, _ := s.st.ListAccounts(r.Context(), sv.ID)
	s.render(w, "server_detail", map[string]any{"Authed": true, "Server": sv, "Accounts": accounts})
}

func (s *Server) render(w http.ResponseWriter, name string, data map[string]any) {
	if err := s.templates.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
