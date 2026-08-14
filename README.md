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

- **Web UI / REST API**：添加服务器并「测试连通」验证主机/凭据/指纹，建/删账户，逐目录配/改权限，改密码，点选「编码/暴露」开关；首页汇总展示已暴露给 agent 的账户。
- **MCP 服务**：`list_exposed_accounts` 工具，向 agent 返回被暴露账户的 `host / ssh_port / username / password / directories`。
- **SSH 执行器**：用 root 凭据在服务器上真实执行 `useradd`、`chpasswd`、`setfacl`（ACL 后端）；非 root 的 sudo 账户自动 `sudo -n` 提权。
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
| `SAL_ENV_FILE` | 否 | `.env` | 覆盖 `.env` 配置文件路径 |

> 以上变量既可走真实环境变量，也可写入项目根目录的 `.env` 文件（`cp .env.example .env` 后按需修改）；**真实环境变量优先于 `.env`**。完整注释见 [.env.example](.env.example)。

## 构建与运行

前置：**Go 1.26+**（`go build` 会读取 go.mod 的版本要求）。

### 一键运行（推荐）

```bash
./run.sh
```

脚本自动完成：生成 `.env`（若缺省，并为 `SAL_MCP_TOKEN` 填入随机强值）→ 构建单二进制 → 启动。首次运行若未设 `SAL_ADMIN_PASSWORD`，随机管理员密码写入 `data/admin-password.txt`（0600），用它登录即可。

### 手动构建与运行

```bash
# 1) 配置（可选）：复制模板并编辑 SAL_MCP_TOKEN / SAL_LISTEN_ADDR 等
cp .env.example .env

# 2) 构建单二进制
go build -o server-agent-link ./cmd/server-agent-link

# 3) 运行（自动读取 .env；真实环境变量优先）
./server-agent-link
```

之后访问 `http://localhost:8080/login` 登录。生产环境建议设置 `SAL_TLS_CERT`/`SAL_TLS_KEY` 启用 HTTPS。

> 需在不装 Go 的机器上部署时，可在有 Go 的机器上交叉编译后拷贝二进制，例如
> `GOOS=linux GOARCH=amd64 go build -o server-agent-link ./cmd/server-agent-link`。

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

## 开发计划（Roadmap）

### 已完成 ✅

- [x] 单 Go 二进制 + 内嵌 SQLite（纯 Go，无外部数据库/运行时）
- [x] Web UI（接线台风格）：服务器 / 账户 / 逐目录权限管理
- [x] 服务器连通性测试（SSH 拨号 + TOFU 主机指纹校验）
- [x] 账户真实建户/删户/改密码/改权限（ACL 后端；非 root 自动 `sudo -n` 提权）
- [x] 账户「编码 / 暴露」开关 + 首页「已暴露给 agent」概览
- [x] MCP 服务 `list_exposed_accounts`（streamable HTTP + Bearer 鉴权）
- [x] 安全：AES-256-GCM 凭据加密、argon2id、HMAC 会话、CSRF、登录限流
- [x] 主密钥持久化（master.key）+ `.env` 配置 + `run.sh` 一键启动

### 规划中 🚧

- [ ] **多云平台接入（阿里云 / 火山引擎等）**：通过云厂商 OpenAPI 拉取 ECS/实例清单并导入服务器，批量下发建户与目录授权；建议先做「只读发现 → 管理员确认导入」再逐步开放自动 provisioning
- [ ] 多管理员 / RBAC 分级权限（当前为单管理员模式）
- [ ] 账户密码轮换与定期自动改密
- [ ] 操作审计日志（谁在何时改了什么）
- [ ] 账户到期自动回收（定时禁用 / 删除）
- [ ] 服务器分组与标签
- [ ] 状态监控与告警（账户 error、连接失败 → webhook 通知）
- [ ] agent 侧 SDK / 客户端，简化 MCP 接入
- [ ] 前端 i18n（英文界面）
- [ ] systemd 服务单元 / 容器化部署

> 规划建议：多云接入建议先抽象出统一的「凭据 + 实例」模型（host/端口/登录用户/密钥来源），再分别对接各家云 SDK——当前 SSH 凭据与 ACL 模型已足够作为底座；云平台只负责「发现实例与注入凭据」，授权仍复用现有 `useradd/setfacl` 链路，避免重复造轮子。
