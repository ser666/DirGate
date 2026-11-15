package main

// ctl 子命令：通过 REST API 管理运行中的 DirGate 服务。
// 复用单二进制（无独立 ctl 分发），所有操作走已部署服务的 HTTP API，
// 凭据（服务地址、管理员密码）从环境变量或 .env 读取。

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strings"
	"time"
)

// ctlEnv 从环境变量/.env 读取服务地址与管理员凭据。
// 服务地址默认 http://127.0.0.1:18080 —— 与 run.sh 的默认端口一致；
// .env 由 config.LoadDotEnv 已在 main 入口加载，此处直接读环境变量。
func ctlBaseURL() string {
	if v := os.Getenv("DG_SERVER_URL"); v != "" {
		return strings.TrimRight(v, "/")
	}
	listen := os.Getenv("DG_LISTEN_ADDR")
	if listen == "" {
		listen = ":8080"
	}
	host := strings.TrimPrefix(listen, ":")
	if host == "" || host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	return "http://127.0.0.1:" + host
}

type ctlClient struct {
	base string
	http *http.Client
	csrf string
}

func newCtlClient() (*ctlClient, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	return &ctlClient{base: ctlBaseURL(), http: &http.Client{Timeout: 30 * time.Second, Jar: jar}}, nil
}

// ctlLogin 用管理员密码登录，缓存 CSRF token 供后续状态变更请求。
func (c *ctlClient) ctlLogin(password string) error {
	body, _ := json.Marshal(map[string]string{"username": os.Getenv("DG_ADMIN_USER"), "password": password})
	if os.Getenv("DG_ADMIN_USER") == "" {
		body, _ = json.Marshal(map[string]string{"username": "admin", "password": password})
	}
	resp, err := c.http.Post(c.base+"/api/login", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("connect %s: %w", c.base, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		return fmt.Errorf("login failed: HTTP %d %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	for _, ck := range resp.Cookies() {
		if ck.Name == "dg_csrf" {
			c.csrf = ck.Value
		}
	}
	return nil
}

// ctlDo 发起已认证请求（自动带 CSRF 头），返回解析后的 JSON。
func (c *ctlClient) ctlDo(method, path string, in any) (map[string]any, error) {
	var rd io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.base+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.csrf != "" {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		var e map[string]string
		_ = json.Unmarshal(b, &e)
		if msg := e["error"]; msg != "" {
			return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, msg)
		}
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	// 列表端点返回 JSON 数组，其余返回对象——统一包成 {"items": ...} 或原样对象。
	if len(b) > 0 && bytes.HasPrefix(bytes.TrimSpace(b), []byte("[")) {
		var arr []any
		if err := json.Unmarshal(b, &arr); err != nil {
			return nil, err
		}
		return map[string]any{"items": arr}, nil
	}
	var out map[string]any
	if len(b) > 0 {
		if err := json.Unmarshal(b, &out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// runCtl 解析并执行 ctl 子命令。用法：
//
//	dirgate ctl <command> [args]
//
// 环境变量：DG_SERVER_URL（服务地址，默认从 DG_LISTEN_ADDR 推导）、
// DG_ADMIN_USER（默认 admin）、DG_ADMIN_PASSWORD（登录密码，必填）。
//
// 命令：
//
//	ctl servers                                     列出服务器
//	ctl server-add <name> <host> [port] [user] [tag] 添加服务器
//	ctl server-test <server-id>                     连通性测试 + 能力探测
//	ctl server-enable <server-id> <on|off>          启用/停用（停用即从 MCP 撤下）
//	ctl server-del <server-id>                      删除服务器（远程删全部账户）
//	ctl accounts <server-id>                        列出账户
//	ctl account-add <server-id> <user> <pass> [dir=mode,dir=mode] [expires]
//	                                                建户并 provision；dir 空格分隔如 /data/a=rw,/data/b=ro
//	ctl account-expose <account-id> <on|off>        暴露开关
//	ctl account-expiry <account-id> <RFC3339|never> 设置到期
//	ctl account-perms <account-id> dir=mode,...     覆盖目录权限
//	ctl account-passwd <account-id> <new-pass>      改密码
//	ctl account-provision <account-id>              重新建户（解锁/修复）
//	ctl account-del <account-id>                    删户
//	ctl exposed                                     查看 MCP 当前暴露面（同 agent 视角）
func runCtl(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, ctlUsage)
		return 2
	}
	// exposed 走 MCP（只需 DG_MCP_TOKEN），不要求管理员登录。
	if args[0] == "exposed" {
		return ctlExposed()
	}
	pw := os.Getenv("DG_ADMIN_PASSWORD")
	if pw == "" {
		fmt.Fprintln(os.Stderr, "ctl: DG_ADMIN_PASSWORD must be set (admin login for the running service)")
		return 2
	}
	c, err := newCtlClient()
	if err != nil {
		fmt.Fprintln(os.Stderr, "ctl:", err)
		return 1
	}
	if err := c.ctlLogin(pw); err != nil {
		fmt.Fprintln(os.Stderr, "ctl:", err)
		return 1
	}

	cmd, rest := args[0], args[1:]
	var out map[string]any
	switch cmd {
	case "servers":
		out, err = c.ctlDo("GET", "/api/servers", nil)
	case "server-add":
		if len(rest) < 3 {
			err = fmt.Errorf("usage: ctl server-add <name> <host> <root-password> [port] [user] [tag]")
			break
		}
		in := map[string]any{"name": rest[0], "host": rest[1], "root_password": rest[2]}
		if len(rest) > 2 {
			var port int
			if _, err := fmt.Sscan(rest[2], &port); err == nil && port > 0 {
				in["ssh_port"] = port
			}
		}
		if len(rest) > 3 {
			var port int
			if _, e := fmt.Sscan(rest[3], &port); e == nil && port > 0 {
				in["ssh_port"] = port
			}
		}
		if len(rest) > 4 {
			in["root_user"] = rest[4]
		}
		if len(rest) > 5 {
			in["tag"] = rest[5]
		}
		out, err = c.ctlDo("POST", "/api/servers", in)
	case "server-test":
		needID := func() string {
			if len(rest) < 1 {
				fmt.Fprintln(os.Stderr, "usage: ctl server-test <server-id>")
				os.Exit(2)
			}
			return rest[0]
		}
		out, err = c.ctlDo("POST", "/api/servers/"+needID()+"/test", map[string]any{})
	case "server-enable":
		if len(rest) < 2 {
			err = fmt.Errorf("usage: ctl server-enable <server-id> <on|off>")
			break
		}
		out, err = c.ctlDo("PUT", "/api/servers/"+rest[0], map[string]any{"enabled": rest[1] == "on"})
	case "server-del":
		if len(rest) < 1 {
			err = fmt.Errorf("usage: ctl server-del <server-id>")
			break
		}
		out, err = c.ctlDo("DELETE", "/api/servers/"+rest[0], nil)
	case "accounts":
		if len(rest) < 1 {
			err = fmt.Errorf("usage: ctl accounts <server-id>")
			break
		}
		out, err = c.ctlDo("GET", "/api/servers/"+rest[0]+"/accounts", nil)
	case "account-add":
		if len(rest) < 3 {
			err = fmt.Errorf("usage: ctl account-add <server-id> <user> <pass> [dirs] [expires]")
			break
		}
		in := map[string]any{"username": rest[1], "password": rest[2], "exposed_to_agent": true}
		if len(rest) > 3 {
			in["permissions"] = parseDirArgs(rest[3])
		}
		if len(rest) > 4 {
			in["expires_at"] = rest[4]
		}
		out, err = c.ctlDo("POST", "/api/servers/"+rest[0]+"/accounts", in)
	case "account-expose":
		if len(rest) < 2 {
			err = fmt.Errorf("usage: ctl account-expose <account-id> <on|off>")
			break
		}
		out, err = c.ctlDo("PUT", "/api/accounts/"+rest[0], map[string]any{"exposed_to_agent": rest[1] == "on"})
	case "account-expiry":
		if len(rest) < 2 {
			err = fmt.Errorf("usage: ctl account-expiry <account-id> <RFC3339|never>")
			break
		}
		exp := rest[1]
		if exp == "never" {
			exp = ""
		}
		out, err = c.ctlDo("PUT", "/api/accounts/"+rest[0], map[string]any{"expires_at": exp})
	case "account-perms":
		if len(rest) < 2 {
			err = fmt.Errorf("usage: ctl account-perms <account-id> dir=mode,...")
			break
		}
		out, err = c.ctlDo("PUT", "/api/accounts/"+rest[0]+"/permissions", parseDirArgs(rest[1]))
	case "account-passwd":
		if len(rest) < 2 {
			err = fmt.Errorf("usage: ctl account-passwd <account-id> <new-pass>")
			break
		}
		out, err = c.ctlDo("PUT", "/api/accounts/"+rest[0]+"/password", map[string]any{"password": rest[1]})
	case "account-provision":
		if len(rest) < 1 {
			err = fmt.Errorf("usage: ctl account-provision <account-id>")
			break
		}
		out, err = c.ctlDo("POST", "/api/accounts/"+rest[0]+"/provision", map[string]any{})
	case "account-del":
		if len(rest) < 1 {
			err = fmt.Errorf("usage: ctl account-del <account-id>")
			break
		}
		out, err = c.ctlDo("DELETE", "/api/accounts/"+rest[0], nil)
	default:
		fmt.Fprintf(os.Stderr, "ctl: unknown command %q\n\n%s", cmd, ctlUsage)
		return 2
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ctl:", err)
		return 1
	}
	enc, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(enc))
	return 0
}

// parseDirArgs 解析 "/data/a=rw,/data/b=ro" 为权限数组。
func parseDirArgs(s string) []map[string]string {
	var out []map[string]string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		mode := "rw"
		if len(kv) == 2 {
			mode = kv[1]
		}
		out = append(out, map[string]string{"path": kv[0], "mode": mode})
	}
	return out
}

// ctlExposed 用 MCP token 调 list_exposed_accounts，输出 agent 视角的暴露面。
func ctlExposed() int {
	token := os.Getenv("DG_MCP_TOKEN")
	if token == "" {
		fmt.Fprintln(os.Stderr, "ctl exposed: DG_MCP_TOKEN must be set")
		return 2
	}
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_exposed_accounts","arguments":{}}}`
	req, _ := http.NewRequest("POST", ctlBaseURL()+"/mcp", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ctl:", err)
		return 1
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var rpc struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal(b, &rpc); err != nil || len(rpc.Result.Content) == 0 {
		fmt.Fprintln(os.Stderr, "ctl exposed: unexpected MCP response")
		return 1
	}
	// 面向人：脱敏展示（密码打码），完整 JSON 仍可经 jq 处理原始输出。
	var view struct {
		Revision string `json:"revision"`
		Accounts []struct {
			ServerName string `json:"server_name"`
			Host       string `json:"host"`
			SSHPort    int    `json:"ssh_port"`
			Username   string `json:"username"`
			Tag        string `json:"tag"`
			ExpiresAt  string `json:"expires_at"`
			Directories []struct {
				Path string `json:"path"`
				Mode string `json:"mode"`
			} `json:"directories"`
		} `json:"accounts"`
	}
	if err := json.Unmarshal([]byte(rpc.Result.Content[0].Text), &view); err != nil {
		fmt.Println(rpc.Result.Content[0].Text)
		return 0
	}
	fmt.Println("revision:", view.Revision)
	for _, a := range view.Accounts {
		dirs := make([]string, 0, len(a.Directories))
		for _, d := range a.Directories {
			dirs = append(dirs, d.Path+"="+d.Mode)
		}
		exp := a.ExpiresAt
		if exp == "" {
			exp = "never"
		}
		fmt.Printf("  %-10s %-22s %-16s %-8s %-8s %s\n", a.ServerName, a.Host+":"+fmt.Sprint(a.SSHPort), a.Username, a.Tag, exp, strings.Join(dirs, ","))
	}
	return 0
}

const ctlUsage = `ctl — manage a running DirGate service over its REST API

environment:
  DG_SERVER_URL      service base URL (default: derived from DG_LISTEN_ADDR, http://127.0.0.1:<port>)
  DG_ADMIN_USER      admin username (default: admin)
  DG_ADMIN_PASSWORD  admin password (required)
  DG_MCP_TOKEN       MCP token (only for ` + "`exposed`" + `)

commands:
  servers                                                list servers
  server-add <name> <host> <root-password> [port] [user] [tag]   add a server
  server-test <server-id>                                connectivity test + tier probe
  server-enable <server-id> <on|off>                     enable / disable (disabled = out of MCP)
  server-del <server-id>                                 delete server (removes all accounts remotely)
  accounts <server-id>                                   list accounts
  account-add <server-id> <user> <pass> [dirs] [expiry]  provision account; dirs like /data/a=rw,/data/b=ro
  account-expose <account-id> <on|off>                   exposure switch
  account-expiry <account-id> <RFC3339|never>            set expiry
  account-perms <account-id> dir=mode,...                overwrite directory permissions
  account-passwd <account-id> <new-pass>                 change password
  account-provision <account-id>                         re-provision (unlock / repair)
  account-del <account-id>                               delete account
  exposed                                                print the MCP view (what agents see)`
