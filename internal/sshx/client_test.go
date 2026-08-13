package sshx

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func startTestServer(t *testing.T) (addr string, hostKeyFingerprint string) {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	config := &ssh.ServerConfig{PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
		if string(pass) == "testpw" {
			return nil, nil
		}
		return nil, fmt.Errorf("bad password")
	}}
	config.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleConn(conn, config)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String(), ssh.FingerprintSHA256(signer.PublicKey())
}

func handleConn(conn net.Conn, config *ssh.ServerConfig) {
	sconn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		return
	}
	defer sconn.Close()
	go ssh.DiscardRequests(reqs)
	for ch := range chans {
		if ch.ChannelType() != "session" {
			ch.Reject(ssh.UnknownChannelType, "unknown")
			continue
		}
		channel, requests, err := ch.Accept()
		if err != nil {
			continue
		}
		go func() {
			for req := range requests {
				switch req.Type {
				case "exec":
					payload := struct{ Command string }{}
					ssh.Unmarshal(req.Payload, &payload)
					channel.Write([]byte("out:" + payload.Command))
					channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
					req.Reply(true, nil)
					channel.Close()
				}
			}
		}()
	}
}

func TestDialRunAndTOFU(t *testing.T) {
	addr, fp := startTestServer(t)
	host, portStr, _ := net.SplitHostPort(addr)
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	// 首次连接，knownHost 为空 → 成功并记录指纹（TOFU）
	c, fp0, err := Dial(host, port, "root", "testpw", "")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	if fp0 != fp {
		t.Fatalf("fingerprint mismatch: got %s want %s", fp0, fp)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := c.Run(ctx, "echo hi")
	if err != nil {
		t.Fatal(err)
	}
	if out != "out:echo hi" {
		t.Fatalf("out=%q", out)
	}

	// 指纹不匹配 → 拒绝
	if _, _, err := Dial(host, port, "root", "testpw", "ssh-rsa AAAA bogus"); err == nil {
		t.Fatal("expected host key mismatch error")
	}

	// 正确指纹 → 通过
	c2, _, err := Dial(host, port, "root", "testpw", fp)
	if err != nil {
		t.Fatalf("dial with fp: %v", err)
	}
	c2.Close()
}
