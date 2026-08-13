package store

import (
	"context"
	"database/sql"

	"serveragentlink/internal/crypto"
)

func (s *Store) CreateAccount(ctx context.Context, serverID, username, password string, codingCapable, exposed bool) (*Account, error) {
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
		CodingCapable: codingCapable, ExposedToAgent: exposed, Status: StatusPending,
		CreatedAt: now, UpdatedAt: now}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO accounts (id,server_id,username,password_enc,coding_capable,exposed_to_agent,status,last_error,created_at,updated_at)
		 VALUES (?,?,?,?,?,?,?,?,?,?)`,
		a.ID, a.ServerID, a.Username, a.PasswordEnc, boolInt(a.CodingCapable), boolInt(a.ExposedToAgent),
		a.Status, a.LastError, a.CreatedAt, a.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return a, nil
}

func (s *Store) GetAccount(ctx context.Context, id string) (*Account, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id,server_id,username,password_enc,coding_capable,exposed_to_agent,status,last_error,created_at,updated_at
		 FROM accounts WHERE id=?`, id)
	return scanAccount(row)
}

func (s *Store) ListAccounts(ctx context.Context, serverID string) ([]Account, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,server_id,username,password_enc,coding_capable,exposed_to_agent,status,last_error,created_at,updated_at
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

func (s *Store) UpdateAccount(ctx context.Context, a Account) error {
	a.UpdatedAt = nowUTC()
	_, err := s.db.ExecContext(ctx,
		`UPDATE accounts SET coding_capable=?,exposed_to_agent=?,status=?,last_error=?,updated_at=? WHERE id=?`,
		boolInt(a.CodingCapable), boolInt(a.ExposedToAgent), a.Status, a.LastError, a.UpdatedAt, a.ID)
	return err
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

func (s *Store) ListExposedAccounts(ctx context.Context) ([]ExposedAccount, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT sv.id, sv.name, sv.host, sv.ssh_port, a.id, a.username, a.password_enc, a.coding_capable
		 FROM accounts a JOIN servers sv ON sv.id = a.server_id
		 WHERE a.exposed_to_agent = 1 ORDER BY sv.name, a.username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ExposedAccount
	for rows.Next() {
		var e ExposedAccount
		var coding int
		if err := rows.Scan(&e.ServerID, &e.ServerName, &e.Host, &e.SSHPort, &e.AccountID,
			&e.Username, &e.PasswordEnc, &coding); err != nil {
			return nil, err
		}
		e.CodingCapable = coding == 1
		perms, err := s.ListPermissions(ctx, e.AccountID)
		if err != nil {
			return nil, err
		}
		e.Directories = perms
		out = append(out, e)
	}
	return out, rows.Err()
}

func scanAccount(r rowScanner) (*Account, error) {
	var a Account
	var coding, exposed int
	err := r.Scan(&a.ID, &a.ServerID, &a.Username, &a.PasswordEnc, &coding, &exposed,
		&a.Status, &a.LastError, &a.CreatedAt, &a.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	a.CodingCapable = coding == 1
	a.ExposedToAgent = exposed == 1
	return &a, nil
}
