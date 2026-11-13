package store

import (
	"context"
	"database/sql"
)

func (s *Store) UpsertAdmin(ctx context.Context, username, passwordHash string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO admin (id,username,password_hash) VALUES (1,?,?)
		 ON CONFLICT(id) DO UPDATE SET username=excluded.username, password_hash=excluded.password_hash`,
		username, passwordHash)
	return err
}

func (s *Store) GetAdmin(ctx context.Context) (*Admin, error) {
	var a Admin
	err := s.db.QueryRowContext(ctx, `SELECT username,password_hash FROM admin WHERE id=1`).Scan(&a.Username, &a.PasswordHash)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}
