package mcp

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"serveragentlink/internal/store"
)

type accountDTO struct {
	ServerID    string   `json:"server_id"`
	ServerName  string   `json:"server_name"`
	Host        string   `json:"host"`
	SSHPort     int      `json:"ssh_port"`
	Username    string   `json:"username"`
	Password    string   `json:"password"`
	Tag         string   `json:"tag,omitempty"` // 服务器语义标签（prod/test/<project>…），供 agent 路由
	ExpiresAt   string   `json:"expires_at"`    // RFC3339，空串 = 永不到期；agent 可自我判断可用窗口
	Directories []dirDTO `json:"directories"`
}

type dirDTO struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
}

type listAccountsArgs struct{}

type listAccountsResult struct {
	// Revision 是凭据目录的全局版本号（当前暴露账户 updated_at 的最大值）。
	// agent 缓存凭据时应保存它：下次调用先比对，变化即说明有改密/到期/开关变更，须刷新本地缓存。
	Revision string       `json:"revision"`
	Accounts []accountDTO `json:"accounts"`
}

// NewHandler 构造一个带静态 Bearer 鉴权的 MCP streamable HTTP handler，
// 暴露 list_exposed_accounts 工具供外部 agent 发现编码账户凭据。
func NewHandler(st *store.Store, key []byte, token string) (http.Handler, error) {
	server := mcp.NewServer(&mcp.Implementation{Name: "server-agent-link", Version: "1.0.0"}, nil)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_exposed_accounts",
		Description: "列出所有已暴露给 agent 的账户：SSH 凭据、目录权限（rw/ro）、tag 与 expires_at（已到期账户自动除外）。返回 revision 为凭据目录版本号——agent 缓存凭据时保存它，下次调用比对变化即需刷新本地缓存。",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in listAccountsArgs) (*mcp.CallToolResult, listAccountsResult, error) {
		rev, err := st.ExposedRevision(ctx)
		if err != nil {
			return nil, listAccountsResult{}, err
		}
		accounts, err := st.ListExposedAccounts(ctx, time.Now().UTC().Format(time.RFC3339Nano))
		if err != nil {
			return nil, listAccountsResult{}, err
		}
		out := listAccountsResult{Revision: rev, Accounts: []accountDTO{}}
		for _, a := range accounts {
			pw, err := st.Decrypt(a.PasswordEnc)
			if err != nil {
				return nil, listAccountsResult{}, err
			}
			dto := accountDTO{ServerID: a.ServerID, ServerName: a.ServerName, Host: a.Host,
				SSHPort: a.SSHPort, Username: a.Username, Password: string(pw),
				Tag: a.Tag, ExpiresAt: a.ExpiresAt}
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
	expected := []byte("Bearer " + token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), expected) != 1 {
			// 显式 JSON 响应（http.Error 会返回 text/plain，令严格 MCP 客户端误判）。
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
			return
		}
		// 凭据目录访问审计：谁（源 IP）何时经 MCP 拉取了凭据。
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		log.Printf("audit user=agent ip=%s action=mcp.%s", host, r.Method)
		next.ServeHTTP(w, r)
	})
}
