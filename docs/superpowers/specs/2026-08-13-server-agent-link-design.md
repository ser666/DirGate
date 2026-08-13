# ServerAgentLink 设计文档

日期：2026-08-13
状态：待评审

## 1. 概述

ServerAgentLink 是一个轻量的「服务器 + 编码账户」管理系统，用于打通部署在服务器上的 Claude Code 与运行在云桌面主机上的个人助手 agent（coclaw/hermes）之间的连通关系，实现「主机个人助手向服务器上的 Claude Code 发任务、收结果」的自动化编码。

系统由两部分组成：

1. **可视化网页平台**（给人用）：添加服务器、在服务器上真实创建/删除 OS 用户、给用户分配逐目录读写权限、标记账户是否具备编码能力、配置是否暴露给 agent。
2. **MCP 服务**（给 agent 用）：按配置对外暴露被标记账户的 SSH 凭据与目录权限清单，agent 拿到后自行 SSH 到服务器并驱动 Claude Code 在授权目录内开发。

### 1.1 目标

- 人为集中管理多台服务器、多个账户及各自的目录权限。
- 每个账户可标记「是否具备编码能力」（`coding_capable`）与「是否暴露给 agent」（`exposed_to_agent`）。
- 通过 MCP 服务，让 agent 能发现所有可接触的编码账户，并拿到连接所需的凭据与权限清单。
- 尽量轻量化、简单，单一二进制部署。

### 1.2 非目标（明确不做）

- **不管理 Anthropic API Key**：Claude Code 的安装、URL / token 等配置由人工在服务器上手动完成；平台仅提供 `coding_capable` 人工标记，不预置、不存储、不转发 API key。
- **不做任务代理**：平台只暴露凭据目录，不代为 SSH、不转发任务、不流式回传结果。agent 自行 SSH 并驱动 Claude Code。
- **不做多用户 / 分级权限**：平台为单管理员模式。
- **不做 agent 本身的开发**：coclaw/hermes 是既有 agent，本系统只提供 MCP 服务供其接入。

## 2. 技术选型

| 项 | 选择 | 理由 |
|---|---|---|
| 语言 | Go | 单静态二进制，部署极轻，SSH 库成熟 |
| MCP SDK | 官方 `modelcontextprotocol/go-sdk` | 新项目长期对齐首选，原生支持 Streamable HTTP（`StreamableHTTPHandler`）与带类型推断的 `AddTool` |
| SSH | `golang.org/x/crypto/ssh` | 标准、稳定 |
| 存储 | SQLite（`modernc.org/sqlite`） | 纯 Go、无 cgo，便于交叉编译单二进制 |
| Web 前端 | `html/template` + htmx + 少量原生 JS，`go:embed` 内嵌 | 无 Node 构建链，符合轻量目标 |
| 加密 | AES-256-GCM + argon2id | 静态加密密码、管理员口令哈希 |
| 路由 | 标准库 `net/http`（Go 1.22+） | 免第三方框架 |

## 3. 架构

单 Go 二进制 `server-agent-link`，部署在任意一台 Linux 主机（通常为云桌面主机本身或一台管理服务器），需满足「管理员浏览器」与「agent」都能通过 HTTP 访问到它。

### 3.1 组件（同进程内）

| 组件 | 职责 | 依赖 |
|---|---|---|
| Web UI | 管理员 CRUD 界面，内嵌 | REST API |
| REST API | 服务器/账户/权限/暴露标记的增删改查 | Store、SSH 执行器 |
| MCP 服务 | streamable HTTP，只读暴露凭据 | Store |
| SSH 执行器 | 用 root 凭据连远程服务器，执行建用户/改密码/设权限 | x/crypto/ssh |
| Store | SQLite 持久化 | — |
| 密钥管理 | 主密钥，加解密存储的密码 | — |

### 3.2 数据流

```
【给人】管理员 → 浏览器 → Web UI → REST API → Store
                              └→ SSH执行器 → 远程服务器(建用户/设权限)

【给agent】agent(coclaw/hermes) → MCP(HTTP+Bearer) → Store(只读，按 exposed 过滤)
        agent 拿到凭据 → 自行 SSH → 远程服务器 → claude code(授权目录内开发)
```

**关键边界**：平台是「凭据目录 + 服务器管理员」，不是任务代理。

## 4. 数据模型

SQLite 表（5 张）：

### 4.1 `servers`
- `id`：主键
- `name`：展示名
- `host`：IP/域名
- `ssh_port`：默认 22
- `root_user`：默认 `root`
- `root_password_enc`：AES-256-GCM 密文
- `host_key`：SSH 指纹（TOFU 用，可空）
- `enabled`：bool
- `last_verified_at`：可空
- `created_at`、`updated_at`

### 4.2 `accounts`
- `id`：主键
- `server_id`：外键 → servers
- `username`
- `password_enc`：AES-256-GCM 密文
- `coding_capable`：bool，人工标记是否具备编码能力
- `exposed_to_agent`：bool，是否暴露给 MCP
- `status`：`pending` | `active` | `error`，反映账户在服务器上的真实创建状态
- `last_error`：可空
- `created_at`、`updated_at`

### 4.3 `directory_permissions`
- `id`：主键
- `account_id`：外键 → accounts
- `path`：服务器上的绝对路径
- `mode`：`rw` | `ro`

### 4.4 `admin`
- 单行：`username`、`password_hash`（argon2id）

### 4.5 `settings`
- 单行键值：`mcp_token_hash`、`permission_backend`（`acl` | `group`）等

### 4.6 账户状态机

```
pending ──建户成功──▶ active
pending ──部分/全部失败──▶ error ──重试(幂等)──▶ active
```

## 5. SSH 执行器

用 `golang.org/x/crypto/ssh`，root 凭据连接；`HostKeyCallback` 采用 TOFU（首次连接记录指纹，之后指纹不匹配则拒绝并告警）；连接与命令均设超时。

### 5.1 建户流程（幂等，root 依次执行）

```bash
id alice                                    # 1. 探测是否已存在
useradd -m -s /bin/bash alice               # 2. 建用户（-m 建 home，claude code 需要 ~/.claude）
echo 'alice:<pwd>' | chpasswd               # 3. 非交互改密码
# 4. 逐目录落地权限（ACL）：
setfacl -m u:alice:rwx /data/projA          # 读写
setfacl -m d:u:alice:rwx /data/projA        # 默认 ACL（新文件继承）
setfacl -m u:alice:rx  /data/projB          # 只读
setfacl -m d:u:alice:rx  /data/projB
```

已存在用户处理：若 `id alice` 命中但 DB 中无对应账户记录（非本平台管理）→ 报错「用户已存在」；若为本平台管理 → 走 5.3 改权限流程（幂等）。

### 5.2 删除流程

```bash
setfacl -x u:alice <path>   # 逐目录移除 ACL（含默认 ACL）
userdel -r alice            # 删除用户及 home
```

### 5.3 改权限（已有账户）

对目录白名单做 diff：新增/变更 → `setfacl -m`；移除 → `setfacl -x`。幂等可重试。

### 5.4 权限后端

- 默认 `acl`（`setfacl`，逐用户逐目录最干净）。
- 服务器无 ACL 时回退 `group`（每目录建组 + `chown :group` + `chmod g+rwx`/`g+rx`）。
- 前置条件写入文档并在 UI 校验提示（`acl` 包已装、目标文件系统已挂 `acl`）。

### 5.5 编码能力检测（可选，非强制）

`coding_capable` 为人工标记。可选提供「验证」按钮执行 `claude --version`（可靠检测：`~/.claude` 存在不代表已装）。平台不配置 Claude Code 的 URL/token。

## 6. MCP 服务契约

- 传输：streamable HTTP，挂载 `/mcp`（官方 go-sdk `StreamableHTTPHandler`）。
- 鉴权：`Authorization: Bearer <mcp_token>`，net/http 中间件在进 handler 前校验，token 存 `settings.mcp_token_hash`。
- 只读，仅一个工具（YAGNI）：

### `list_exposed_accounts()`

返回所有 `exposed_to_agent=true` 的账户：

```json
[
  {
    "server_id": "...",
    "server_name": "研发机A",
    "host": "10.0.0.5",
    "ssh_port": 22,
    "username": "alice",
    "password": "<读时解密>",
    "coding_capable": true,
    "directories": [
      {"path": "/data/projA", "mode": "rw"},
      {"path": "/data/projB", "mode": "ro"}
    ]
  }
]
```

agent 拿到后自行 SSH、自行 `claude -p`。平台不转发任务。

## 7. 安全

- **静态加密**：主密钥来自 env `SAL_MASTER_KEY`（32 字节 hex）或首次运行生成到 `0600` keyfile；所有密码（root、账户）用 AES-256-GCM 加密落库；日志/错误绝不出现明文密码。
- **Web 管理员**：单管理员，argon2id 哈希；session cookie + CSRF token；登录限流。
- **MCP**：静态 Bearer token，与管理员密码分离，可独立轮换。
- **SSH**：TOFU 指纹校验，指纹变化即拒绝并告警。

## 8. 错误处理

- SSH 连接失败/部分失败 → 账户 `status=error` + `last_error`，UI 可重试（幂等）。
- MCP 读失败 → JSON-RPC 错误码。
- Store 错误 → HTTP 500 + 日志。

## 9. 测试策略

- 单元测试：Store CRUD、加密往返、MCP 工具 handler（mock store）、权限白名单 diff。
- 集成测试：SSH 执行器对真实 sshd 容器（docker）跑 useradd/setfacl 幂等与错误路径。
- MCP：真实 MCP client 或 curl JSON-RPC 冒烟。

## 10. 部署

- `go build` → 单二进制 + 内嵌前端。
- `./server-agent-link` 运行，env 配置：监听地址、数据目录、`SAL_MASTER_KEY`、`SAL_MCP_TOKEN`、管理员初始密码。
- 首次运行 bootstrap：创建管理员、生成主密钥（若未提供）。

## 11. 参考

- 官方 MCP Go SDK 设计文档：https://github.com/modelcontextprotocol/go-sdk/blob/main/design/design.md
- mcp-go vs 官方 SDK 对比：https://github.com/klarlabs-studio/mcp-go/blob/v1.10.0/docs/COMPARISON.md
- Claude Code 无头调用（agent 侧驱动方式，实测）：
  - `claude -p --output-format json|stream-json`，`-p` 模式无需 PTY（无需 `ssh -t`）。
  - 免交互：`--dangerously-skip-permissions`（或 `--permission-mode bypassPermissions`），`--add-dir` 限制目录。
  - 非登录账户鉴权：`ANTHROPIC_API_KEY` 环境变量（`claude login` 为浏览器 OAuth，无法程序化预置）。
  - 能力检测：`claude --version`。
