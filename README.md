# ServerAgentLink

**单个静态二进制。零外部依赖。拷贝即跑。**把多台服务器的目录安全地暴露给本地 agent：OS 账户供给 + 逐目录 ACL 授权 + MCP 凭据目录，让 agent 在多服务器环境下安全干活。

> English version: [README_EN.md](README_EN.md)

一个本地助理 agent 往往要同时在多台服务器上工作（读写代码仓、查日志、改配置）。ServerAgentLink 解决的是这件事的**权限底座**：

- **给人用**（Web UI）：登记服务器 → 在服务器上真实创建 OS 账户 → 按目录授予只读/读写 ACL → 决定哪些账户暴露给 agent、何时到期回收。
- **给 agent 用**（MCP）：一个只读工具 `list_exposed_accounts`，agent 一次调用拿到全部被授权的「服务器 + 账户 + 目录清单」，随后在**且仅在**授权目录内工作——越界访问在 OS 层就被拒绝。

核心思路是**授权即边界**：agent 不是拿着 root 密码四处跑，而是拿到一批最小权限的 OS 账户；服务器上真正的访问控制由 POSIX ACL 执行，平台只负责供给与回收。

它**不做**任务代理（不编排 agent），也**不管理** Anthropic API Key——与 orca 之类编排 ADE 正交：agent 先经这里取得凭据授权，才谈得上被谁编排。

## Agent 5 分钟接入

```bash
# 1) 拿账户（一次性，缓存到 agent 上下文）：每台服务器有哪些账户、哪些目录可读写
curl -s -H "Authorization: Bearer $SAL_MCP_TOKEN" \
     -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
     -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_exposed_accounts","arguments":{}}}' \
     http://sal-host:8080/mcp

# 2) 在授权目录内工作（任意 agent 工作流：编码、查日志、改配置……）
sshpass -p '<password>' ssh -o StrictHostKeyChecking=accept-new \
  coder1@10.0.0.5 -p 22 \
  'cd /data/repo && <任意命令>'
```

或在任何支持 MCP 的 agent 里挂 streamable HTTP 端点 `http://sal-host:8080/mcp`，Header 带 `Authorization: Bearer <SAL_MCP_TOKEN>`。

以驱动 Claude Code 为例：agent 拿到凭据后 `ssh` 到目标服务器，在授权目录里执行 `claude -p "任务" --dangerously-skip-permissions`——Claude Code 只是授权目录里的一种用法，平台本身不关心 agent 在目录里跑什么。

管理员的操作全部在 Web UI 完成：添加服务器（root 账号/密码）→ 建账户（真实 OS 用户 + 逐目录 ACL）→ 打开「暴露」开关。agent 侧无需任何配置。

## 架构

```
┌─────────────┐        ┌──────────────────────────────────────────┐
│   浏览器      │  HTTP  │  ServerAgentLink（单 Go 二进制）          │
│  (Web UI)    ├───────►│                                          │
└─────────────┘        │  Web UI（内嵌模板） ──► REST API          │
                       │        │                  │               │
┌─────────────┐        │        ▼                  ▼               │
│  本地 agent   │  MCP   │  MCP 服务(streamable HTTP, Bearer)       │
│ (coclaw/     ├───────►│   list_exposed_accounts（只读）           │
│  hermes/任意) │        │        │                                  │
└─────────────┘        │        ▼                                  │
                       │  SSH 执行器（root 凭据：useradd/chpasswd/  │
                       │  setfacl/usermod）                        │
                       │        │                                  │
                       │  SQLite 存储（AES-256-GCM 加密凭据，       │
                       │  user_version 版本化迁移）                 │
                       │        │                                  │
                       │  到期回收器（10 分钟扫描：锁定到期 OS 账户）│
                       └───────────────┬──────────────────────────┘
                                       │ SSH (root)
                       ┌───────────────┴──────────────┐
                       │  服务器 A        服务器 B …    │
                       │  (OS 账户 + 逐目录 ACL)        │
                       └──────────────────────────────┘
```

- **Web UI / REST API**：添加服务器并「测试连通」验证主机/凭据/指纹，建/删账户，逐目录配/改权限（含删户时撤销 ACL），改密码，点选「编码/暴露」开关，设置账户到期时间；首页汇总展示当前暴露给 agent 的账户（到期账户自动消失）。
- **MCP 服务**：`list_exposed_accounts` 工具，向 agent 返回被暴露且未到期的账户的 `host / ssh_port / username / password / directories`。
- **SSH 执行器**：用 root 凭据在服务器上真实执行 `useradd`、`chpasswd`、`setfacl`、`userdel`、`usermod -L`（到期锁定）；非 root 的 sudo 账户自动 `sudo -n` 提权。
- **到期回收**：每 10 分钟扫描，到期账户先停止 MCP 暴露，再锁定远端 OS 账户（封密码 + nologin，不删数据；管理员可在 UI 删除或续期后「重新建户」恢复）。
- **SQLite 存储**：账户密码用 AES-256-GCM 加密落库；管理员密码用 argon2id 哈希；`PRAGMA user_version` 版化迁移，升级不炸库。

## 安全模型

agent 在服务器上的实际权限边界由四层共同构成：

1. **OS 账户隔离**：每个被暴露账户是独立 OS 用户，不与 root 或他人共享凭据；进程级隔离（home、umask、shell）天然存在。
2. **逐目录 ACL**：`setfacl` 精确到目录的 `rw`/`ro` 授权（含默认 ACL，新文件自动继承）；白名单之外的一切路径按服务器原有权限语义拒绝。
3. **平台侧开关**：`exposed_to_agent` 决定凭据是否出现在 MCP 目录；到期（`expires_at`）决定暴露何时自动终止——MCP 立即消失，远端账户随后锁定。
4. **平台自身安全**：凭据 AES-256-GCM 加密落库、MCP 静态 Bearer、管理员 argon2id + HMAC 会话 + CSRF + 登录限流、SSH TOFU 指纹、操作审计日志。

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

## MCP 返回示例

`list_exposed_accounts` 只返回 `exposed_to_agent=1`、服务器 `enabled=1` 且**未到期**的账户：

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

## 安全与运维

- 账户密码与服务器 root 密码在数据库中经 **AES-256-GCM**（nonce‖密文）加密，密钥来自 `SAL_MASTER_KEY`（或 `master.key` 文件，0600 权限）。**db 与 master.key 必须成对备份**：`./deploy/backup.sh` 一键打包。
- 管理员密码用 **argon2id** 哈希，绝不落明文。
- 会话用 **HMAC-SHA256 签名 cookie**（`SameSite=Strict`、`HttpOnly`，启用 TLS 时加 `Secure`），登录限流 5 次/分钟/IP（原子计数，不信任 `X-Forwarded-For`）。
- 状态变更接口启用 **double-submit CSRF**（`sal_csrf` cookie + `X-CSRF-Token` 头）。
- SSH 首次连接采用 **TOFU** 主机密钥校验（记录 SHA256 指纹），防止中间人；换主机/重装可 `reset_host_key` 复位。
- MCP 端点暴露明文凭据，必须通过 `SAL_MCP_TOKEN` 强鉴权，并仅在内网/受信环境暴露。
- 服务端日志与操作审计（`audit user=... action=...`）写 stdout；systemd 部署下用 `journalctl -t server-agent-link` 检索。
- 生产部署：systemd 单元模板见 [deploy/server-agent-link.service](deploy/server-agent-link.service)（含最小权限加固与自动重启）。

更完整的使用与运维说明见 [docs/使用说明.md](docs/使用说明.md)。

## 测试

```bash
go test ./...                                   # 单元测试
go test -tags integration ./internal/sshx/      # 可选：需 docker sshd（见 integration_test.go 前置）
```

## 开发计划（Roadmap）

### 已完成 ✅

- [x] 单 Go 二进制 + 内嵌 SQLite（纯 Go，无外部数据库/运行时；`user_version` 版本化迁移，旧库自动升级）
- [x] Web UI（接线台风格）：服务器 / 账户 / 逐目录权限管理
- [x] 服务器连通性测试（SSH 拨号 + TOFU 主机指纹校验）
- [x] 账户真实建户/删户/改密码/改权限（ACL 后端；非 root 自动 `sudo -n` 提权；删户前撤销逐目录 ACL）
- [x] 账户「编码 / 暴露」开关 + 首页「已暴露给 agent」概览
- [x] **账户到期自动回收**（`expires_at` → MCP 停止暴露 → OS 账户锁定，可续期恢复）
- [x] MCP 服务 `list_exposed_accounts`（streamable HTTP + Bearer 鉴权）
- [x] 安全：AES-256-GCM 凭据加密、argon2id、HMAC 会话、CSRF、登录限流
- [x] 服务端日志 + 操作审计（`audit` 行，stdout/journald）
- [x] 主密钥持久化（master.key）+ `.env` 配置 + `run.sh` 一键启动
- [x] 部署物：systemd 单元模板 + 备份脚本（`deploy/`）

### 规划中 🚧

- [ ] **多云平台接入（阿里云 / 火山引擎等）**：通过云厂商 OpenAPI 拉取 ECS/实例清单并导入服务器，批量下发建户与目录授权；建议先做「只读发现 → 管理员确认导入」再逐步开放自动 provisioning
- [ ] 账户密码轮换与定期自动改密
- [ ] 服务器分组与标签
- [ ] 状态监控与告警（账户 error、连接失败 → webhook 通知）

### 明确不做（保持轻量定位）

- 多管理员 / RBAC（单管理员 + 审计日志已覆盖内网自托管场景）
- agent 编排 / worktree 扇出 / harness 预设（orca 赛道）
- Anthropic API Key 管理 / token 成本治理
- K8s / 容器化平台（单静态二进制 + systemd 已够）

> 规划建议：多云接入建议先抽象出统一的「凭据 + 实例」模型（host/端口/登录用户/密钥来源），再分别对接各家云 SDK——当前 SSH 凭据与 ACL 模型已足够作为底座；云平台只负责「发现实例与注入凭据」，授权仍复用现有 `useradd/setfacl` 链路，避免重复造轮子。
