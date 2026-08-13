package mcp

import (
	"context"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"serveragentlink/internal/store"
)

type accountDTO struct {
	ServerID      string   `json:"server_id"`
	ServerName    string   `json:"server_name"`
	Host          string   `json:"host"`
	SSHPort       int      `json:"ssh_port"`
	Username      string   `json:"username"`
	Password      string   `json:"password"`
	CodingCapable bool     `json:"coding_capable"`
	Directories   []dirDTO `json:"directories"`
}

type dirDTO struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
}

type listAccountsArgs struct{}

type listAccountsResult struct {
	Accounts []accountDTO `json:"accounts"`
}

// NewHandler 构造一个带静态 Bearer 鉴权的 MCP streamable HTTP handler，
// 暴露 list_exposed_accounts 工具供外部 agent 发现编码账户凭据。
func NewHandler(st *store.Store, key []byte, token string) (http.Handler, error) {
	server := mcp.NewServer(&mcp.Implementation{Name: "server-agent-link", Version: "1.0.0"}, nil)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_exposed_accounts",
		Description: "列出所有已暴露给 agent 的编码账户及其 SSH 凭据与目录权限",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in listAccountsArgs) (*mcp.CallToolResult, listAccountsResult, error) {
		accounts, err := st.ListExposedAccounts(ctx)
		if err != nil {
			return nil, listAccountsResult{}, err
		}
		out := listAccountsResult{Accounts: []accountDTO{}}
		for _, a := range accounts {
			pw, err := st.Decrypt(a.PasswordEnc)
			if err != nil {
				return nil, listAccountsResult{}, err
			}
			dto := accountDTO{ServerID: a.ServerID, ServerName: a.ServerName, Host: a.Host,
				SSHPort: a.SSHPort, Username: a.Username, Password: string(pw), CodingCapable: a.CodingCapable}
			for _, p := range a.Directories {
				dto.Directories = append(dto.Directories, dirDTO{Path: p.Path, Mode: p.Mode})
			}
			out.Accounts = append(out.Accounts, dto)
		}
		return nil, out, nil
	})

	streamable := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server },
		&mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})

	return bearerAuth(token, streamable), nil
}

func bearerAuth(token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
