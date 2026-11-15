package httpapi

import (
	"context"
	"encoding/json"
	"errors"

	"net/http"
	"time"

	"serveragentlink/internal/sshx"
	"serveragentlink/internal/store"
)

var (
	errBadExpiry             = errors.New("expires_at must be RFC3339 (e.g. 2026-12-31T23:59:59+08:00) or empty")
	errAttachAccountMismatch = errors.New("plain-mode servers can only attach the admin account itself (username must equal the server's admin user)")
)

type accountInput struct {
	Username       string            `json:"username"`
	Password       string            `json:"password"`
	ExposedToAgent bool              `json:"exposed_to_agent"`
	ExpiresAt      string            `json:"expires_at"`
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
	ExposedToAgent bool              `json:"exposed_to_agent"`
	Status         string            `json:"status"`
	LastError      string            `json:"last_error"`
	ExpiresAt      string            `json:"expires_at"`
	Permissions    []permissionInput `json:"permissions"`
}

func toAccountDTO(a store.Account, perms []store.DirectoryPermission) accountDTO {
	dto := accountDTO{ID: a.ID, ServerID: a.ServerID, Username: a.Username,
		ExposedToAgent: a.ExposedToAgent,
		Status:         a.Status, LastError: a.LastError, ExpiresAt: a.ExpiresAt, Permissions: []permissionInput{}}
	for _, p := range perms {
		dto.Permissions = append(dto.Permissions, permissionInput{Path: p.Path, Mode: p.Mode})
	}
	return dto
}

func (s *Server) handleListAccounts(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("id")
	if _, err := s.st.GetServer(r.Context(), serverID); err != nil {
		writeErr(w, r, http.StatusNotFound, "not found", err)
		return
	}
	accounts, err := s.st.ListAccounts(r.Context(), serverID)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "db error", err)
		return
	}
	out := make([]accountDTO, 0, len(accounts))
	for _, a := range accounts {
		perms, err := s.st.ListPermissions(r.Context(), a.ID)
		if err != nil {
			writeErr(w, r, http.StatusInternalServerError, "db error", err)
			return
		}
		out = append(out, toAccountDTO(a, perms))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleCreateAccount(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("id")
	var in accountInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, r, http.StatusBadRequest, "invalid json", err)
		return
	}
	if in.Username == "" || in.Password == "" {
		writeErr(w, r, http.StatusBadRequest, "username/password required", nil)
		return
	}
	if err := validateExpiresAt(in.ExpiresAt); err != nil {
		writeErr(w, r, http.StatusBadRequest, err.Error(), nil)
		return
	}
	// plain（attach-only）服务器：只允许 attach 管理账户本人，提前拒绝避免留半截记录。
	if sv, err := s.st.GetServer(r.Context(), serverID); err == nil && sv.AccessMode == store.AccessPlain && in.Username != sv.RootUser {
		writeErr(w, r, http.StatusBadRequest, errAttachAccountMismatch.Error(), nil)
		return
	}
	a, err := s.st.CreateAccount(r.Context(), serverID, in.Username, in.Password, in.ExposedToAgent)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "create failed", err)
		return
	}
	if in.ExpiresAt != "" {
		a.ExpiresAt = in.ExpiresAt
		if err := s.st.UpdateAccount(r.Context(), *a); err != nil {
			writeErr(w, r, http.StatusInternalServerError, "set expiry failed", err)
			return
		}
	}
	if err := s.st.SetPermissions(r.Context(), a.ID, toStorePerms(in.Permissions)); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "set perms failed", err)
		return
	}
	s.audit(r, "account.create", a.ID+" "+a.Username)
	s.provision(r, a)
	writeAccount(w, r, s, a.ID, http.StatusCreated)
}

func (s *Server) handleProvisionAccount(w http.ResponseWriter, r *http.Request) {
	a, err := s.st.GetAccount(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, r, http.StatusNotFound, "not found", err)
		return
	}
	s.audit(r, "account.provision", a.ID+" "+a.Username)
	s.provision(r, a)
	writeAccount(w, r, s, a.ID, http.StatusOK)
}

// writeAccount 取回最新账户+权限并返回 DTO（建户与重试共用同一应答形状）。
func writeAccount(w http.ResponseWriter, r *http.Request, s *Server, id string, code int) {
	a, err := s.st.GetAccount(r.Context(), id)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "get account failed", err)
		return
	}
	perms, err := s.st.ListPermissions(r.Context(), a.ID)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "db error", err)
		return
	}
	writeJSON(w, code, toAccountDTO(*a, perms))
}

// provision 在服务器上落地账户：按服务器 access_mode 分流——
//
//	root/sudo：真实建户（useradd+chpasswd+ACL），可建新用户；
//	plain（attach-only）：不建户，验证已存在账户的密码后仅授 ACL（限自己拥有的目录）。
func (s *Server) provision(r *http.Request, a *store.Account) {
	sv, err := s.st.GetServer(r.Context(), a.ServerID)
	if err != nil {
		s.markError(r, a.ID, err)
		return
	}
	adminPw, err := s.st.Decrypt(sv.RootPasswordEnc)
	if err != nil {
		s.markError(r, a.ID, err)
		return
	}
	acctPw, err := s.st.Decrypt(a.PasswordEnc)
	if err != nil {
		s.markError(r, a.ID, err)
		return
	}
	perms, err := s.st.ListPermissions(r.Context(), a.ID)
	if err != nil {
		s.markError(r, a.ID, err)
		return
	}
	spec := sshx.UserSpec{Username: a.Username, Password: string(acctPw)}
	for _, p := range perms {
		spec.Permissions = append(spec.Permissions, sshx.PermissionSpec{Path: p.Path, Mode: p.Mode})
	}
	var fp string
	if sv.AccessMode == store.AccessPlain {
		// plain（attach-only）：账户必须是管理账户本人，密码须与远端真实账户一致（AttachVerify 即认证）。
		if a.Username != sv.RootUser {
			s.markError(r, a.ID, errAttachAccountMismatch)
			return
		}
		fp, err = s.exec.AttachVerify(r.Context(), sv.Host, sv.SSHPort, spec.Username, spec.Password, sv.HostKey)
		if err == nil && len(spec.Permissions) > 0 {
			fp, err = s.exec.AttachSetPermissions(r.Context(), sv.Host, sv.SSHPort, sv.RootUser, string(adminPw), fp, spec.Permissions, nil)
		}
	} else { // root / sudo / 未探测：脚本自身探测提权路径
		fp, err = s.exec.CreateUser(r.Context(), sv.Host, sv.SSHPort, sv.RootUser, string(adminPw), sv.HostKey, spec)
	}
	if err != nil {
		logRemoteErr(r, "provision "+a.Username, err)
		s.markError(r, a.ID, err)
		return
	}
	s.persistHostKey(r.Context(), sv, fp)
	if err := s.st.MarkAccountActive(r.Context(), a.ID); err != nil {
		logRemoteErr(r, "mark active "+a.ID, err)
	}
}

// persistHostKey 在成功 SSH 后回写观察到的指纹（TOFU 固定）。
func (s *Server) persistHostKey(ctx context.Context, sv *store.Server, fp string) {
	if fp != "" && fp != sv.HostKey {
		sv.HostKey = fp
		_ = s.st.UpdateServer(ctx, *sv)
	}
}

// markError 只更新状态列，不做读-改-写整行覆盖，避免吞掉并发的标志位变更。
func (s *Server) markError(r *http.Request, accountID string, err error) {
	if lerr := s.st.MarkAccountError(r.Context(), accountID, err.Error()); lerr != nil {
		logRemoteErr(r, "mark error "+accountID, lerr)
	}
}

func (s *Server) handleUpdateAccount(w http.ResponseWriter, r *http.Request) {
	a, err := s.st.GetAccount(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, r, http.StatusNotFound, "not found", err)
		return
	}
	var in struct {
		ExposedToAgent *bool   `json:"exposed_to_agent"`
		ExpiresAt      *string `json:"expires_at"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, r, http.StatusBadRequest, "invalid json", err)
		return
	}
	if in.ExposedToAgent != nil {
		a.ExposedToAgent = *in.ExposedToAgent
	}
	if in.ExpiresAt != nil {
		if err := validateExpiresAt(*in.ExpiresAt); err != nil {
			writeErr(w, r, http.StatusBadRequest, err.Error(), nil)
			return
		}
		a.ExpiresAt = *in.ExpiresAt
	}
	if err := s.st.UpdateAccount(r.Context(), *a); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "update failed", err)
		return
	}
	s.audit(r, "account.update", a.ID+" "+a.Username)
	perms, err := s.st.ListPermissions(r.Context(), a.ID)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "db error", err)
		return
	}
	writeJSON(w, http.StatusOK, toAccountDTO(*a, perms))
}

// validateExpiresAt 接受空串（永不到期）或 RFC3339 时刻。
// 允许过去时刻：管理员可能要标记「视同已到期」让账户立即失效。
func validateExpiresAt(v string) error {
	if v == "" {
		return nil
	}
	if _, err := time.Parse(time.RFC3339, v); err != nil {
		return errBadExpiry
	}
	return nil
}

// handleChangePassword 在服务器上重置该 OS 用户的密码，并同步更新加密存储。
// 复用 CreateUser（幂等：useradd||skip + chpasswd），不改动目录 ACL。
func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	a, err := s.st.GetAccount(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, r, http.StatusNotFound, "not found", err)
		return
	}
	var in struct {
		Password string `json:"password"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil || in.Password == "" {
		writeErr(w, r, http.StatusBadRequest, "password required", nil)
		return
	}
	sv, err := s.st.GetServer(r.Context(), a.ServerID)
	if err != nil {
		writeErr(w, r, http.StatusNotFound, "not found", err)
		return
	}
	adminPw, err := s.st.Decrypt(sv.RootPasswordEnc)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "decrypt admin password failed", err)
		return
	}
	// plain 模式无法改 OS 密码（无特权）；attach 账户密码须与服务器真实账户保持一致，改密请直接在服务器上 passwd。
	if sv.AccessMode == store.AccessPlain {
		writeErr(w, r, http.StatusBadRequest, "plain-mode: cannot change OS password without privileges; run passwd on the server and update the account here with the same password", nil)
		return
	}
	spec := sshx.UserSpec{Username: a.Username, Password: in.Password}
	fp, err := s.exec.CreateUser(r.Context(), sv.Host, sv.SSHPort, sv.RootUser, string(adminPw), sv.HostKey, spec)
	if err != nil {
		logRemoteErr(r, "change password "+a.Username, err)
		s.markError(r, a.ID, err)
		writeErr(w, r, http.StatusBadGateway, "change password failed", err)
		return
	}
	s.persistHostKey(r.Context(), sv, fp)
	enc, err := s.st.Encrypt([]byte(in.Password))
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "encrypt failed", err)
		return
	}
	if err := s.st.UpdateAccountPassword(r.Context(), a.ID, enc); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "persist failed", err)
		return
	}
	s.audit(r, "account.password", a.ID+" "+a.Username)
	writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
}

func (s *Server) handleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	a, err := s.st.GetAccount(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, r, http.StatusNotFound, "not found", err)
		return
	}
	sv, err := s.st.GetServer(r.Context(), a.ServerID)
	if err != nil {
		writeErr(w, r, http.StatusNotFound, "not found", err)
		return
	}
	adminPw, err := s.st.Decrypt(sv.RootPasswordEnc)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "decrypt admin password failed", err)
		return
	}
	perms, err := s.st.ListPermissions(r.Context(), a.ID)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "db error", err)
		return
	}
	// 删户：先逐目录撤销 ACL 再 userdel（root/sudo）；plain 模式不删 OS 用户，仅撤 ACL 并删记录。
	var fp string
	if sv.AccessMode == store.AccessPlain {
		var revoked []sshx.PermissionSpec
		for _, p := range perms {
			revoked = append(revoked, sshx.PermissionSpec{Path: p.Path, Mode: p.Mode})
		}
		fp, err = s.exec.AttachLock(r.Context(), sv.Host, sv.SSHPort, sv.RootUser, string(adminPw), sv.HostKey, revoked)
	} else {
		spec := sshx.UserSpec{Username: a.Username}
		for _, p := range perms {
			spec.Permissions = append(spec.Permissions, sshx.PermissionSpec{Path: p.Path, Mode: p.Mode})
		}
		fp, err = s.exec.DeleteUser(r.Context(), sv.Host, sv.SSHPort, sv.RootUser, string(adminPw), sv.HostKey, spec)
	}
	if err != nil {
		// 远端删户失败则不删库，保留记录供重试，避免留下无 UI 记录的孤儿账户。
		logRemoteErr(r, "delete user "+a.Username, err)
		s.markError(r, a.ID, err)
		writeErr(w, r, http.StatusBadGateway, "delete user failed", err)
		return
	}
	s.persistHostKey(r.Context(), sv, fp)
	if err := s.st.DeleteAccount(r.Context(), a.ID); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "delete account failed", err)
		return
	}
	s.audit(r, "account.delete", a.ID+" "+a.Username)
	writeNoContent(w)
}

func (s *Server) handleListPermissions(w http.ResponseWriter, r *http.Request) {
	perms, err := s.st.ListPermissions(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "db error", err)
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
	a, err := s.st.GetAccount(r.Context(), accountID)
	if err != nil {
		writeErr(w, r, http.StatusNotFound, "not found", err)
		return
	}
	var in []permissionInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, r, http.StatusBadRequest, "invalid json", err)
		return
	}
	newPerms := toStorePerms(in)
	oldPerms, err := s.st.ListPermissions(r.Context(), accountID)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "db error", err)
		return
	}
	if err := s.st.SetPermissions(r.Context(), accountID, newPerms); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "set perms failed", err)
		return
	}
	// 改权限真实应用到服务器（含撤销被移除目录的 ACL）；失败则标记账户 error，DB 更新仍保留。
	sv, err := s.st.GetServer(r.Context(), a.ServerID)
	if err != nil {
		writeErr(w, r, http.StatusNotFound, "not found", err)
		return
	}
	adminPw, err := s.st.Decrypt(sv.RootPasswordEnc)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "decrypt admin password failed", err)
		return
	}
	var granted, removedSpec []sshx.PermissionSpec
	for _, p := range newPerms {
		granted = append(granted, sshx.PermissionSpec{Path: p.Path, Mode: p.Mode})
	}
	for _, old := range oldPerms {
		if !hasPerm(newPerms, old) {
			removedSpec = append(removedSpec, sshx.PermissionSpec{Path: old.Path, Mode: old.Mode})
		}
	}
	var fp string
	if sv.AccessMode == store.AccessPlain {
		if a.Username != sv.RootUser {
			writeErr(w, r, http.StatusBadRequest, errAttachAccountMismatch.Error(), nil)
			return
		}
		fp, err = s.exec.AttachSetPermissions(r.Context(), sv.Host, sv.SSHPort, sv.RootUser, string(adminPw), sv.HostKey, granted, removedSpec)
	} else {
		spec := sshx.UserSpec{Username: a.Username, Permissions: granted, Removed: removedSpec}
		fp, err = s.exec.UpdatePermissions(r.Context(), sv.Host, sv.SSHPort, sv.RootUser, string(adminPw), sv.HostKey, spec)
	}
	if err != nil {
		logRemoteErr(r, "apply permissions "+a.Username, err)
		s.markError(r, a.ID, err)
		writeErr(w, r, http.StatusBadGateway, "apply permissions failed", err)
		return
	}
	s.persistHostKey(r.Context(), sv, fp)
	s.audit(r, "account.permissions", a.ID+" "+a.Username)
	writeJSON(w, http.StatusOK, in)
}

func hasPerm(perms []store.DirectoryPermission, p store.DirectoryPermission) bool {
	for _, x := range perms {
		if x.Path == p.Path {
			return true
		}
	}
	return false
}

func toStorePerms(in []permissionInput) []store.DirectoryPermission {
	out := make([]store.DirectoryPermission, 0, len(in))
	for _, p := range in {
		if p.Path == "" {
			continue
		}
		if p.Mode != store.ModeReadWrite && p.Mode != store.ModeReadOnly {
			continue
		}
		out = append(out, store.DirectoryPermission{Path: p.Path, Mode: p.Mode})
	}
	return out
}
