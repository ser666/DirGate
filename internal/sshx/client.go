package sshx

import (
	"context"
	"fmt"
	"io"
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
	return c.RunStdin(ctx, cmd, "")
}

// RunStdin 执行命令，把 stdinData 写入远端命令的 stdin。
// 用于把敏感输入（如 chpasswd 的 username:password）经加密通道传送，
// 避免出现在远端命令行（ps）中。
func (c *Client) RunStdin(ctx context.Context, cmd, stdinData string) (string, error) {
	sess, err := c.client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()

	if stdinData != "" {
		stdin, err := sess.StdinPipe()
		if err != nil {
			return "", err
		}
		go func() {
			defer stdin.Close()
			_, _ = io.WriteString(stdin, stdinData)
		}()
	}

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
		// 关闭底层连接中止会话，令 Output 尽快返回；随后等待 worker 结束，
		// 避免与 defer sess.Close() 并发关闭同一个 session。
		_ = c.client.Close()
		<-ch
		return "", ctx.Err()
	}
}

func (c *Client) Close() error { return c.client.Close() }
