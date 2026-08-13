package store

import (
	"context"
	"testing"
)

func TestServerCRUD(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	sv, err := s.CreateServer(ctx, "dev1", "10.0.0.5", 22, "root", "rootpw")
	if err != nil {
		t.Fatal(err)
	}
	if sv.ID == "" || sv.SSHPort != 22 {
		t.Fatal("bad server")
	}
	// 密码已加密落库，不等于明文
	if string(sv.RootPasswordEnc) == "rootpw" {
		t.Fatal("password not encrypted")
	}

	got, err := s.GetServer(ctx, sv.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Host != "10.0.0.5" {
		t.Fatalf("host=%q", got.Host)
	}

	got.Name = "dev1-renamed"
	if err := s.UpdateServer(ctx, *got); err != nil {
		t.Fatal(err)
	}
	got2, _ := s.GetServer(ctx, sv.ID)
	if got2.Name != "dev1-renamed" {
		t.Fatal("update failed")
	}

	list, _ := s.ListServers(ctx)
	if len(list) != 1 {
		t.Fatalf("list len=%d", len(list))
	}

	if err := s.DeleteServer(ctx, sv.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetServer(ctx, sv.ID); err == nil {
		t.Fatal("expected not found")
	}
}
