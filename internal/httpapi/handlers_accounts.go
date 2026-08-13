package httpapi

import (
	"encoding/json"
	"net/http"

	"serveragentlink/internal/sshx"
	"serveragentlink/internal/store"
)

type accountInput struct {
	Username       string            `json:"username"`
	Password       string            `json:"password"`
	CodingCapable  bool              `json:"coding_capable"`
	ExposedToAgent bool              `json:"exposed_to_agent"`
	Permissions    []permissionInput `json:"permissions"`
}

type permissionInput struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
}

type accountDTO struct {
	ID             string            `json:"id"`
	ServerID       string            `json:"server_id"`
	Username       string            `json:"username"`
	CodingCapable  bool              `json:"coding_capable"`
	ExposedToAgent bool              `json:"exposed_to_agent"`
	Status         string            `json:"status"`
	LastError      string            `json:"last_error"`
	Permissions    []permissionInput `json:"permissions"`
}

func toAccountDTO(a store.Account, perms []store.DirectoryPermission) accountDTO {
	dto := accountDTO{ID: a.ID, ServerID: a.ServerID, Username: a.Username,
		CodingCapable: a.CodingCapable, ExposedToAgent: a.ExposedToAgent,
		Status: a.Status, LastError: a.LastError, Permissions: []permissionInput{}}
	for _, p := range perms {
		dto.Permissions = append(dto.Permissions, permissionInput{Path: p.Path, Mode: p.Mode})
	}
	return dto
}

func (s *Server) handleCreateAccount(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("id")
	var in accountInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if in.Username == "" || in.Password == "" {
		writeErr(w, http.StatusBadRequest, "username/password required")
		return
	}
	a, err := s.st.CreateAccount(r.Context(), serverID, in.Username, in.Password, in.CodingCapable, in.ExposedToAgent)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "create failed")
		return
	}
	if err := s.st.SetPermissions(r.Context(), a.ID, toStorePerms(in.Permissions)); err != nil {
		writeErr(w, http.StatusInternalServerError, "set perms failed")
		return
	}
	s.provision(r, a)
	acc, _ := s.st.GetAccount(r.Context(), a.ID)
	perms, _ := s.st.ListPermissions(r.Context(), a.ID)
	writeJSON(w, http.StatusCreated, toAccountDTO(*acc, perms))
}

func (s *Server) handleProvisionAccount(w http.ResponseWriter, r *http.Request) {
	a, err := s.st.GetAccount(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	s.provision(r, a)
	acc, _ := s.st.GetAccount(r.Context(), a.ID)
	perms, _ := s.st.ListPermissions(r.Context(), a.ID)
	writeJSON(w, http.StatusOK, toAccountDTO(*acc, perms))
}

// provision 用 root 凭据在服务器上真实建户；失败时标记 status=error。
func (s *Server) provision(r *http.Request, a *store.Account) {
	sv, err := s.st.GetServer(r.Context(), a.ServerID)
	if err != nil {
		s.markError(r, a.ID, err)
		return
	}
	rootPw, err := s.st.Decrypt(sv.RootPasswordEnc)
	if err != nil {
		s.markError(r, a.ID, err)
		return
	}
	acctPw, err := s.st.Decrypt(a.PasswordEnc)
	if err != nil {
		s.markError(r, a.ID, err)
		return
	}
	perms, _ := s.st.ListPermissions(r.Context(), a.ID)
	spec := sshx.UserSpec{Username: a.Username, Password: string(acctPw)}
	for _, p := range perms {
		spec.Permissions = append(spec.Permissions, sshx.PermissionSpec{Path: p.Path, Mode: p.Mode})
	}
	fp, err := s.exec.CreateUser(r.Context(), sv.Host, sv.SSHPort, sv.RootUser, string(rootPw), sv.HostKey, spec)
	if err != nil {
		s.markError(r, a.ID, err)
		return
	}
	if fp != "" && fp != sv.HostKey {
		sv.HostKey = fp
		_ = s.st.UpdateServer(r.Context(), *sv)
	}
	a.Status = store.StatusActive
	a.LastError = ""
	_ = s.st.UpdateAccount(r.Context(), *a)
}

func (s *Server) markError(r *http.Request, accountID string, err error) {
	_ = s.st.UpdateAccount(r.Context(), store.Account{ID: accountID, Status: store.StatusError, LastError: err.Error()})
}

func (s *Server) handleUpdateAccount(w http.ResponseWriter, r *http.Request) {
	a, err := s.st.GetAccount(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	var in struct {
		CodingCapable  *bool `json:"coding_capable"`
		ExposedToAgent *bool `json:"exposed_to_agent"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if in.CodingCapable != nil {
		a.CodingCapable = *in.CodingCapable
	}
	if in.ExposedToAgent != nil {
		a.ExposedToAgent = *in.ExposedToAgent
	}
	if err := s.st.UpdateAccount(r.Context(), *a); err != nil {
		writeErr(w, http.StatusInternalServerError, "update failed")
		return
	}
	perms, _ := s.st.ListPermissions(r.Context(), a.ID)
	writeJSON(w, http.StatusOK, toAccountDTO(*a, perms))
}

func (s *Server) handleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	a, err := s.st.GetAccount(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	sv, err := s.st.GetServer(r.Context(), a.ServerID)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	rootPw, _ := s.st.Decrypt(sv.RootPasswordEnc)
	spec := sshx.UserSpec{Username: a.Username, Password: ""}
	_ = s.exec.DeleteUser(r.Context(), sv.Host, sv.SSHPort, sv.RootUser, string(rootPw), spec)
	_ = s.st.DeleteAccount(r.Context(), a.ID)
	writeJSON(w, http.StatusNoContent, nil)
}

func (s *Server) handleListPermissions(w http.ResponseWriter, r *http.Request) {
	perms, err := s.st.ListPermissions(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	out := []permissionInput{}
	for _, p := range perms {
		out = append(out, permissionInput{Path: p.Path, Mode: p.Mode})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleSetPermissions(w http.ResponseWriter, r *http.Request) {
	accountID := r.PathValue("id")
	var in []permissionInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if err := s.st.SetPermissions(r.Context(), accountID, toStorePerms(in)); err != nil {
		writeErr(w, http.StatusInternalServerError, "set perms failed")
		return
	}
	writeJSON(w, http.StatusOK, in)
}

func toStorePerms(in []permissionInput) []store.DirectoryPermission {
	out := make([]store.DirectoryPermission, 0, len(in))
	for _, p := range in {
		if p.Mode != store.ModeReadWrite && p.Mode != store.ModeReadOnly {
			continue
		}
		out = append(out, store.DirectoryPermission{Path: p.Path, Mode: p.Mode})
	}
	return out
}
