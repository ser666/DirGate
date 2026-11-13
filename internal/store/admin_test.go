package store

import (
	"context"
	"testing"
)

func TestAdminUpsertGet(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertAdmin(ctx, "admin", "hash1"); err != nil {
		t.Fatal(err)
	}
	a, err := s.GetAdmin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if a.Username != "admin" || a.PasswordHash != "hash1" {
		t.Fatalf("%+v", a)
	}
	_ = s.UpsertAdmin(ctx, "admin", "hash2")
	a2, _ := s.GetAdmin(ctx)
	if a2.PasswordHash != "hash2" {
		t.Fatal("upsert failed")
	}
}
