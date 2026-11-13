package httpapi

import (
	"encoding/json"
	"net/http"

	"serveragentlink/internal/sshx"
	"serveragentlink/internal/store"
)

type serverInput struct {
	Name         string `json:"name"`
	Host         string `json:"host"`
	SSHPort      int    `json:"ssh_port"`
	RootUser     string `json:"root_user"`
	RootPassword string `json:"root_password"`
	ResetHostKey bool   `json:"reset_host_key"`
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
		writeErr(w, r, http.StatusInternalServerError, "db error", err)
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
		writeErr(w, r, http.StatusBadRequest, "invalid json", err)
		return
	}
	if in.Name == "" || in.Host == "" || in.RootPassword == "" {
		writeErr(w, r, http.StatusBadRequest, "name/host/root_password required", nil)
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
		writeErr(w, r, http.StatusInternalServerError, "create failed", err)
		return
	}
	s.audit(r, "server.create", sv.ID+" "+sv.Name)
	writeJSON(w, http.StatusCreated, toServerDTO(*sv))
}

func (s *Server) handleGetServer(w http.ResponseWriter, r *http.Request) {
	sv, err := s.st.GetServer(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, r, http.StatusNotFound, "not found", err)
		return
	}
	writeJSON(w, http.StatusOK, toServerDTO(*sv))
}

func (s *Server) handleUpdateServer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	sv, err := s.st.GetServer(r.Context(), id)
	if err != nil {
		writeErr(w, r, http.StatusNotFound, "not found", err)
		return
	}
	var in serverInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, r, http.StatusBadRequest, "invalid json", err)
		return
	}
	if in.Name != "" {
		sv.Name = in.Name
	}
	if in.Host != "" && in.Host != sv.Host {
		// 主机变更后旧指纹失效，清空以触发下次 TOFU 重新固定。
		sv.Host = in.Host
		sv.HostKey = ""
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
			writeErr(w, r, http.StatusInternalServerError, "encrypt failed", err)
			return
		}
		sv.RootPasswordEnc = enc
	}
	if in.ResetHostKey {
		sv.HostKey = ""
	}
	if err := s.st.UpdateServer(r.Context(), *sv); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "update failed", err)
		return
	}
	s.audit(r, "server.update", sv.ID)
	writeJSON(w, http.StatusOK, toServerDTO(*sv))
}

// handleTestServer 用已存 root 凭据做一次真实 SSH 拨号 + 无害命令，
// 验证主机可达 / root 密码正确 / 主机指纹匹配，成功后固定指纹并记录验证时间。
// 连通失败返回 200 + connected:false（这是测试结果，而非服务器内部错误）。
func (s *Server) handleTestServer(w http.ResponseWriter, r *http.Request) {
	sv, err := s.st.GetServer(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, r, http.StatusNotFound, "not found", err)
		return
	}
	rootPw, err := s.st.Decrypt(sv.RootPasswordEnc)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "decrypt root password failed", err)
		return
	}
	fp, err := s.exec.TestConnection(r.Context(), sv.Host, sv.SSHPort, sv.RootUser, string(rootPw), sv.HostKey)
	if err != nil {
		logRemoteErr(r, "server.test "+sv.ID, err)
		writeJSON(w, http.StatusOK, map[string]any{"connected": false, "error": err.Error()})
		return
	}
	if err := s.st.MarkServerVerified(r.Context(), sv.ID, fp); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "persist failed", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"connected": true, "host_key": fp})
}

func (s *Server) handleDeleteServer(w http.ResponseWriter, r *http.Request) {
	sv, err := s.st.GetServer(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, r, http.StatusNotFound, "not found", err)
		return
	}
	accounts, err := s.st.ListAccounts(r.Context(), sv.ID)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "db error", err)
		return
	}
	if len(accounts) > 0 {
		rootPw, err := s.st.Decrypt(sv.RootPasswordEnc)
		if err != nil {
			writeErr(w, r, http.StatusInternalServerError, "decrypt root password failed", err)
			return
		}
		for _, a := range accounts {
			perms, err := s.st.ListPermissions(r.Context(), a.ID)
			if err != nil {
				writeErr(w, r, http.StatusInternalServerError, "db error", err)
				return
			}
			spec := sshx.UserSpec{Username: a.Username}
			for _, p := range perms {
				spec.Permissions = append(spec.Permissions, sshx.PermissionSpec{Path: p.Path, Mode: p.Mode})
			}
			if _, err := s.exec.DeleteUser(r.Context(), sv.Host, sv.SSHPort, sv.RootUser, string(rootPw), sv.HostKey, spec); err != nil {
				// 远端删户失败则保留服务器及账户记录，供重试，避免留下孤儿 OS 用户。
				logRemoteErr(r, "server.delete remote user "+a.Username, err)
				writeErr(w, r, http.StatusBadGateway, "delete remote user "+a.Username+" failed", err)
				return
			}
		}
	}
	if err := s.st.DeleteServer(r.Context(), sv.ID); err != nil {
		writeErr(w, r, http.StatusNotFound, "not found", err)
		return
	}
	s.audit(r, "server.delete", sv.ID+" "+sv.Name)
	writeNoContent(w)
}
