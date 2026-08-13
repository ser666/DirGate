//go:build integration

package sshx

import (
	"context"
	"testing"
	"time"
)

// 前置：docker run -d --rm -p 2222:22 -e ROOT_PASSWORD=rootpw panubo/sshd
func TestCreateUserAgainstDocker(t *testing.T) {
	spec := UserSpec{Username: "ituser", Password: "itpw",
		Permissions: []PermissionSpec{{Path: "/home/ituser", Mode: "rw"}}}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := (&Executor{}).CreateUser(ctx, "127.0.0.1", 2222, "root", "rootpw", "", spec)
	if err != nil {
		t.Fatal(err)
	}
}
