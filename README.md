# ServerAgentLink

一个轻量级的自动编码系统，连接「服务器上部署的 Claude Code」与「云桌面宿主机上的个人助理 agent」。

平台是一个**凭据目录 + 服务器管理员**：管理员在 Web UI 中添加服务器（root 账号/密码）、在服务器上创建/删除真实 OS 用户、按目录授予读写权限、标记「编码能力」、并决定是否把账户「暴露」给 agent。agent 通过一个只读的 MCP 服务发现这些被暴露的编码账户及其 SSH 凭据，进而在被授权的目录里驱动 Claude Code。

它**不做**任务代理，也**不管理** Anthropic API Key——Claude Code 需在服务器上手工安装并配置。

## 架构

```
┌─────────────┐        ┌──────────────────────────────────────────┐
│   浏览器      │  HTTP  │  ServerAgentLink（单 Go 二进制）          │
│  (Web UI)    ├───────►│                                          │
└─────────────┘        │  Web UI（内嵌模板） ──► REST API          │
                       │        │                  │               │
┌─────────────┐        │        ▼                  ▼               │
│  agent       │  MCP   │  MCP 服务(streamable HTTP, Bearer)       │
│ (coclaw/     ├───────►│   list_exposed_accounts（只读）           │
│  hermes)     │        │        │                                  │
└─────────────┘        │        ▼                                  │
                       │  SSH 执行器（root 凭据：useradd/chpasswd/  │
                       │  setfacl）                                │
                       │        │                                  │
                       │  SQLite 存储（AES-256-GCM 加密凭据）       │
                       └───────────────┬──────────────────────────┘
                                       │ SSH (root)
                             ┌─────────▼──────────┐
                             │  目标服务器          │
                             │  (Claude Code + 目录)│
                             └────────────────────┘
```

- **Web UI / REST API**：添加服务器、建/删账户、配目录权限、标记编码能力与暴露。
- **MCP 服务**：`list_exposed_accounts` 工具，向 agent 返回被暴露账户的 `host / ssh_port / username / password / directories`。
- **SSH 执行器**：用 root 凭据在服务器上真实执行 `useradd`、`chpasswd`、`setfacl`（ACL 后端）。
- **SQLite 存储**：账户密码用 AES-256-GCM 加密落库；管理员密码用 argon2id 哈希。

## 环境变量

| 变量 | 必填 | 默认 | 说明 |
|---|---|---|---|
| `SAL_LISTEN_ADDR` | 否 | `:8080` | 监听地址 |
| `SAL_DATA_DIR` | 否 | `./data` | 数据目录（SQLite + master.key） |
| `SAL_MASTER_KEY` | 否 | 自动生成 | 32 字节 hex 主密钥；缺省时生成到 `$SAL_DATA_DIR/master.key` |
| `SAL_MCP_TOKEN` | **是** | — | MCP 端点的静态 Bearer token |
| `SAL_ADMIN_USER` | 否 | `admin` | 管理员用户名 |
| `SAL_ADMIN_PASSWORD` | 否 | 自动生成 | 首次运行的管理员密码；缺省时写入 `$SAL_DATA_DIR/admin-password.txt`（0600） |
| `SAL_TLS_CERT` | 否 | — | TLS 证书路径（与 `SAL_TLS_KEY` 成对设置） |
| `SAL_TLS_KEY` | 否 | — | TLS 私钥路径（与 `SAL_TLS_CERT` 成对设置） |

## 构建与运行

```bash
# 构建单二进制
go build -o server-agent-link ./cmd/server-agent-link

# 运行（首次运行自动创建管理员，缺省密码时写入 admin-password.txt）
SAL_MCP_TOKEN=devtoken \
SAL_MASTER_KEY=$(openssl rand -hex 32) \
./server-agent-link
```

首次运行若未设 `SAL_ADMIN_PASSWORD`，随机密码会写入 `$SAL_DATA_DIR/admin-password.txt`（0600，不落日志）。之后访问 `http://localhost:8080/login` 登录。生产环境建议设置 `SAL_TLS_CERT`/`SAL_TLS_KEY` 启用 HTTPS。

## ACL 前置条件

权限后端为 `acl`（唯一支持的后端），要求目标服务器满足：

1. 安装 `acl` 包（Debian/Ubuntu：`apt-get install acl`）。
2. 被授权目录所在文件系统需以 `acl` 选项挂载（`mount -o remount,acl /` 或 `/etc/fstab` 加 `acl`）。

否则 `setfacl` 会失败，账户状态将标记为 `error`。

## MCP 接入示例

agent 用 streamable HTTP 连接，带 `Authorization: Bearer <SAL_MCP_TOKEN>`：

```bash
curl -H "Authorization: Bearer devtoken" \
     -H "Content-Type: application/json" \
     -H "Accept: application/json, text/event-stream" \
     -X POST \
     -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_exposed_accounts","arguments":{}}}' \
     http://localhost:8080/mcp
```

返回示例：

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "content": [{
      "type": "text",
      "text": "{\"accounts\":[{\"server_id\":\"...\",\"server_name\":\"dev1\",\"host\":\"10.0.0.5\",\"ssh_port\":22,\"username\":\"coder1\",\"password\":\"...\",\"coding_capable\":true,\"directories\":[{\"path\":\"/data/repo\",\"mode\":\"rw\"}]}]}"
    }]
  }
}
```

agent 侧拿到账户后，在授权的目录里用 SSH 驱动 Claude Code：

```bash
sshpass -p '<password>' ssh -o StrictHostKeyChecking=accept-new \
  coder1@10.0.0.5 -p 22 \
  'cd /data/repo && claude -p "实现 <任务>" --dangerously-skip-permissions'
```

## 安全说明

- 账户密码与服务器 root 密码在数据库中经 **AES-256-GCM**（nonce‖密文）加密，密钥来自 `SAL_MASTER_KEY`（或 `master.key` 文件，0600 权限）。
- 管理员密码用 **argon2id** 哈希，绝不落明文。
- 会话用 **HMAC-SHA256 签名 cookie**（`SameSite=Strict`、`HttpOnly`，启用 TLS 时加 `Secure`），登录限流 5 次/分钟/IP（原子计数，不信任 `X-Forwarded-For`）。
- 状态变更接口启用 **double-submit CSRF**（`sal_csrf` cookie + `X-CSRF-Token` 头）。
- SSH 首次连接采用 **TOFU** 主机密钥校验（记录 SHA256 指纹），防止中间人；换主机/重装可 `reset_host_key` 复位。
- MCP 端点暴露明文凭据，必须通过 `SAL_MCP_TOKEN` 强鉴权，并仅在内网/受信环境暴露。

更完整的使用与运维说明见 [docs/使用说明.md](docs/使用说明.md)。

## 测试

```bash
go test ./...                                   # 单元测试
go test -tags integration ./internal/sshx/      # 可选：需 docker sshd（见 integration_test.go 前置）
```
