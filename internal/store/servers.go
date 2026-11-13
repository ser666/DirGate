package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"serveragentlink/internal/crypto"
)

var ErrNotFound = errors.New("not found")

func nowUTC() string { return time.Now().UTC().Format(time.RFC3339Nano) }

func (s *Store) CreateServer(ctx context.Context, name, host string, port int, rootUser, rootPassword string) (*Server, error) {
	id, err := crypto.RandomID()
	if err != nil {
		return nil, err
	}
	enc, err := s.Encrypt([]byte(rootPassword))
	if err != nil {
		return nil, err
	}
	now := nowUTC()
	sv := &Server{ID: id, Name: name, Host: host, SSHPort: port, RootUser: rootUser,
		RootPasswordEnc: enc, Enabled: true, CreatedAt: now, UpdatedAt: now}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO servers (id,name,host,ssh_port,root_user,root_password_enc,host_key,enabled,last_verified_at,access_mode,created_at,updated_at)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		sv.ID, sv.Name, sv.Host, sv.SSHPort, sv.RootUser, sv.RootPasswordEnc, sv.HostKey, boolInt(sv.Enabled), sv.LastVerifiedAt, sv.AccessMode, now, now)
	if err != nil {
		return nil, err
	}
	return sv, nil
}

func (s *Store) GetServer(ctx context.Context, id string) (*Server, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id,name,host,ssh_port,root_user,root_password_enc,host_key,enabled,last_verified_at,access_mode,created_at,updated_at
		 FROM servers WHERE id=?`, id)
	return scanServer(row)
}

func (s *Store) ListServers(ctx context.Context) ([]Server, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,name,host,ssh_port,root_user,root_password_enc,host_key,enabled,last_verified_at,access_mode,created_at,updated_at
		 FROM servers ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Server
	for rows.Next() {
		sv, err := scanServer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *sv)
	}
	return out, rows.Err()
}

func (s *Store) UpdateServer(ctx context.Context, sv Server) error {
	sv.UpdatedAt = nowUTC()
	_, err := s.db.ExecContext(ctx,
		`UPDATE servers SET name=?,host=?,ssh_port=?,root_user=?,root_password_enc=?,host_key=?,enabled=?,last_verified_at=?,access_mode=?,updated_at=? WHERE id=?`,
		sv.Name, sv.Host, sv.SSHPort, sv.RootUser, sv.RootPasswordEnc, sv.HostKey, boolInt(sv.Enabled), sv.LastVerifiedAt, sv.AccessMode, nowUTC(), sv.ID)
	return err
}

// MarkServerVerified 记录一次成功的连通性验证：固定主机指纹并写入验证时间。
func (s *Store) MarkServerVerified(ctx context.Context, id, fp string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE servers SET host_key=?, last_verified_at=?, updated_at=? WHERE id=?`,
		fp, nowUTC(), nowUTC(), id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateServerAccessMode 单列写入管理能力级别（探测结果），避免整行覆盖。
func (s *Store) UpdateServerAccessMode(ctx context.Context, id, mode string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE servers SET access_mode=?, updated_at=? WHERE id=?`, mode, nowUTC(), id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) DeleteServer(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM servers WHERE id=?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

type rowScanner interface{ Scan(dest ...any) error }

func scanServer(r rowScanner) (*Server, error) {
	var sv Server
	var enabled int
	err := r.Scan(&sv.ID, &sv.Name, &sv.Host, &sv.SSHPort, &sv.RootUser, &sv.RootPasswordEnc,
		&sv.HostKey, &enabled, &sv.LastVerifiedAt, &sv.AccessMode, &sv.CreatedAt, &sv.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	sv.Enabled = enabled == 1
	return &sv, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
