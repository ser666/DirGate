package httpapi

import (
	"encoding/json"
	"net/http"

	"serveragentlink/internal/store"
)

type serverInput struct {
	Name         string `json:"name"`
	Host         string `json:"host"`
	SSHPort      int    `json:"ssh_port"`
	RootUser     string `json:"root_user"`
	RootPassword string `json:"root_password"`
}

// serverDTO 是 server 的对外视图，绝不包含 RootPasswordEnc。
type serverDTO struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Host     string `json:"host"`
	SSHPort  int    `json:"ssh_port"`
	RootUser string `json:"root_user"`
	Enabled  bool   `json:"enabled"`
}

func toServerDTO(sv store.Server) serverDTO {
	return serverDTO{ID: sv.ID, Name: sv.Name, Host: sv.Host, SSHPort: sv.SSHPort,
		RootUser: sv.RootUser, Enabled: sv.Enabled}
}

func (s *Server) handleListServers(w http.ResponseWriter, r *http.Request) {
	servers, err := s.st.ListServers(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	out := make([]serverDTO, 0, len(servers))
	for _, sv := range servers {
		out = append(out, toServerDTO(sv))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleCreateServer(w http.ResponseWriter, r *http.Request) {
	var in serverInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if in.Name == "" || in.Host == "" || in.RootPassword == "" {
		writeErr(w, http.StatusBadRequest, "name/host/root_password required")
		return
	}
	if in.SSHPort == 0 {
		in.SSHPort = 22
	}
	if in.RootUser == "" {
		in.RootUser = "root"
	}
	sv, err := s.st.CreateServer(r.Context(), in.Name, in.Host, in.SSHPort, in.RootUser, in.RootPassword)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "create failed")
		return
	}
	writeJSON(w, http.StatusCreated, toServerDTO(*sv))
}

func (s *Server) handleGetServer(w http.ResponseWriter, r *http.Request) {
	sv, err := s.st.GetServer(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, toServerDTO(*sv))
}

func (s *Server) handleUpdateServer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	sv, err := s.st.GetServer(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	var in serverInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if in.Name != "" {
		sv.Name = in.Name
	}
	if in.Host != "" {
		sv.Host = in.Host
	}
	if in.SSHPort != 0 {
		sv.SSHPort = in.SSHPort
	}
	if in.RootUser != "" {
		sv.RootUser = in.RootUser
	}
	if in.RootPassword != "" {
		enc, err := s.st.Encrypt([]byte(in.RootPassword))
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "encrypt failed")
			return
		}
		sv.RootPasswordEnc = enc
	}
	if err := s.st.UpdateServer(r.Context(), *sv); err != nil {
		writeErr(w, http.StatusInternalServerError, "update failed")
		return
	}
	writeJSON(w, http.StatusOK, toServerDTO(*sv))
}

func (s *Server) handleDeleteServer(w http.ResponseWriter, r *http.Request) {
	if err := s.st.DeleteServer(r.Context(), r.PathValue("id")); err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusNoContent, nil)
}
