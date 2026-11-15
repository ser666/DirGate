package store

import (
	"context"
	"database/sql"

	"dirgate/internal/crypto"
)

func (s *Store) CreateAccount(ctx context.Context, serverID, username, password string, exposed bool) (*Account, error) {
	id, err := crypto.RandomID()
	if err != nil {
		return nil, err
	}
	enc, err := s.Encrypt([]byte(password))
	if err != nil {
		return nil, err
	}
	now := nowUTC()
	a := &Account{ID: id, ServerID: serverID, Username: username, PasswordEnc: enc,
		ExposedToAgent: exposed, Status: StatusPending,
		CreatedAt: now, UpdatedAt: now}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO accounts (id,server_id,username,password_enc,exposed_to_agent,status,last_error,expires_at,created_at,updated_at)
		 VALUES (?,?,?,?,?,?,?,?,?,?)`,
		a.ID, a.ServerID, a.Username, a.PasswordEnc, boolInt(a.ExposedToAgent),
		a.Status, a.LastError, a.ExpiresAt, a.CreatedAt, a.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return a, nil
}

func (s *Store) GetAccount(ctx context.Context, id string) (*Account, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id,server_id,username,password_enc,exposed_to_agent,status,last_error,expires_at,created_at,updated_at
		 FROM accounts WHERE id=?`, id)
	return scanAccount(row)
}

func (s *Store) ListAccounts(ctx context.Context, serverID string) ([]Account, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,server_id,username,password_enc,exposed_to_agent,status,last_error,expires_at,created_at,updated_at
		 FROM accounts WHERE server_id=? ORDER BY username`, serverID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Account
	for rows.Next() {
		a, err := scanAccount(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

// UpdateAccount 只更新标志与状态列，不触碰密码密文，避免读-改-写覆盖并发变更。
func (s *Store) UpdateAccount(ctx context.Context, a Account) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE accounts SET exposed_to_agent=?,status=?,last_error=?,expires_at=?,updated_at=? WHERE id=?`,
		boolInt(a.ExposedToAgent), a.Status, a.LastError, a.ExpiresAt, nowUTC(), a.ID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateAccountPassword 单独更新账户的加密密码（不触碰其它字段，供「改密码」使用）。
func (s *Store) UpdateAccountPassword(ctx context.Context, id string, passwordEnc []byte) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE accounts SET password_enc=?, updated_at=? WHERE id=?`, passwordEnc, nowUTC(), id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// MarkAccountLocked 到期回收用：锁定 OS 账户后记录状态。
func (s *Store) MarkAccountLocked(ctx context.Context, id, reason string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE accounts SET status=?, last_error=?, updated_at=? WHERE id=?`,
		StatusLocked, reason, nowUTC(), id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// MarkAccountError 只写状态与错误信息，避免读-改-写覆盖并发的标志位变更。
func (s *Store) MarkAccountError(ctx context.Context, id, msg string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE accounts SET status=?, last_error=?, updated_at=? WHERE id=?`,
		StatusError, msg, nowUTC(), id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// MarkAccountActive provision 成功后清除错误状态（不改标志位/密码）。
func (s *Store) MarkAccountActive(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE accounts SET status=?, last_error='', updated_at=? WHERE id=?`,
		StatusActive, nowUTC(), id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// ListExpiringAccounts 返回已到期（expires_at 非空且已过）且尚未锁定的账户，
// 供回收器逐个锁定 OS 用户。
func (s *Store) ListExpiringAccounts(ctx context.Context, now string) ([]Account, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,server_id,username,password_enc,exposed_to_agent,status,last_error,expires_at,created_at,updated_at
		 FROM accounts WHERE expires_at != '' AND expires_at <= ? AND status != ?`,
		now, StatusLocked)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Account
	for rows.Next() {
		a, err := scanAccount(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

func (s *Store) DeleteAccount(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM accounts WHERE id=?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) SetPermissions(ctx context.Context, accountID string, perms []DirectoryPermission) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM directory_permissions WHERE account_id=?`, accountID); err != nil {
		return err
	}
	for _, p := range perms {
		id, err := crypto.RandomID()
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO directory_permissions (id,account_id,path,mode) VALUES (?,?,?,?)`,
			id, accountID, p.Path, p.Mode); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) ListPermissions(ctx context.Context, accountID string) ([]DirectoryPermission, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,account_id,path,mode FROM directory_permissions WHERE account_id=? ORDER BY path`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DirectoryPermission
	for rows.Next() {
		var p DirectoryPermission
		if err := rows.Scan(&p.ID, &p.AccountID, &p.Path, &p.Mode); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ExposedRevision 返回当前暴露目录的全局版本号（暴露账户 updated_at 的最大值，空目录返回空串）。
// 供 MCP 输出 revision 字段，agent 据此判断凭据是否变更。
func (s *Store) ExposedRevision(ctx context.Context) (string, error) {
	var rev sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT MAX(a.updated_at) FROM accounts a JOIN servers sv ON sv.id = a.server_id
		 WHERE a.exposed_to_agent = 1 AND sv.enabled = 1`).Scan(&rev)
	if err != nil {
		return "", err
	}
	return rev.String, nil
}

// ListExposedAccounts 一次性 JOIN 取出暴露账户及其目录权限，供 MCP 与首页概览复用；
// 到期账户（expires_at 已过）不再暴露。
func (s *Store) ListExposedAccounts(ctx context.Context, now string) ([]ExposedAccount, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT sv.id, sv.name, sv.host, sv.ssh_port, a.id, a.username, a.password_enc, a.expires_at, sv.tag,
		        p.path, p.mode
		 FROM accounts a
		 JOIN servers sv ON sv.id = a.server_id
		 LEFT JOIN directory_permissions p ON p.account_id = a.id
		 WHERE a.exposed_to_agent = 1 AND sv.enabled = 1
		   AND (a.expires_at = '' OR a.expires_at > ?)
		 ORDER BY sv.name, a.username, p.path`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ExposedAccount
	for rows.Next() {
		var e ExposedAccount
		var path, mode sql.NullString
		if err := rows.Scan(&e.ServerID, &e.ServerName, &e.Host, &e.SSHPort, &e.AccountID,
			&e.Username, &e.PasswordEnc, &e.ExpiresAt, &e.Tag, &path, &mode); err != nil {
			return nil, err
		}
		if path.Valid { // LEFT JOIN 无权限的账户只有一行 NULL
			e.Directories = append(e.Directories, DirectoryPermission{Path: path.String, Mode: mode.String})
		}
		// 同一账户的多行权限合并进已出现的条目。
		if n := len(out); n > 0 && out[n-1].AccountID == e.AccountID {
			out[n-1].Directories = append(out[n-1].Directories, e.Directories...)
			continue
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func scanAccount(r rowScanner) (*Account, error) {
	var a Account
	var exposed int
	err := r.Scan(&a.ID, &a.ServerID, &a.Username, &a.PasswordEnc, &exposed,
		&a.Status, &a.LastError, &a.ExpiresAt, &a.CreatedAt, &a.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	a.ExposedToAgent = exposed == 1
	return &a, nil
}
