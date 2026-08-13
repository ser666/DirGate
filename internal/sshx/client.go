package sshx

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"
)

type Client struct {
	client *ssh.Client
}

// Dial 连接远程主机并返回新指纹。knownHost 为上次记录的指纹（SHA256），空表示首次连接（TOFU）。
// 若已知指纹与实际不符，返回错误。
func Dial(host string, port int, user, password, knownHost string) (*Client, string, error) {
	var lastFP string
	cfg := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			lastFP = ssh.FingerprintSHA256(key)
			if knownHost == "" {
				return nil
			}
			if knownHost != lastFP {
				return fmt.Errorf("host key mismatch: got %s want %s", lastFP, knownHost)
			}
			return nil
		},
		Timeout: 10 * time.Second,
	}
	client, err := ssh.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)), cfg)
	if err != nil {
		return nil, "", err
	}
	return &Client{client: client}, lastFP, nil
}

// Run 执行命令并返回合并的 stdout/stderr，受 ctx 取消控制。
func (c *Client) Run(ctx context.Context, cmd string) (string, error) {
	sess, err := c.client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()

	type result struct {
		out string
		err error
	}
	ch := make(chan result, 1)
	go func() {
		out, err := sess.Output(cmd)
		ch <- result{out: string(out), err: err}
	}()

	select {
	case r := <-ch:
		return r.out, r.err
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func (c *Client) Close() error { return c.client.Close() }
