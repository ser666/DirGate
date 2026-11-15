# ServerAgentLink

**单个静态二进制。零外部依赖。拷贝即跑。**
把多台服务器的目录安全地暴露给本地 agent —— OS 账户供给 + 逐目录 ACL 授权 + MCP 凭据目录。

[English](README.md) · [User Guide](docs/USER_GUIDE_EN.md)

## 为什么

本地助理 agent 常要同时跨多台服务器工作（读写代码仓、查日志、改配置），但直接把 root 密码交给 agent 既危险又无法审计。ServerAgentLink 是这件事的**权限底座**：

- 管理员在 Web UI 里登记服务器，为 agent 批量创建**最小权限 OS 账户**，按目录授予 `rw`/`ro` ACL；
- agent 通过一个 MCP 工具拿到全部被授权的「服务器 + 账户 + 目录清单」，**且仅在**授权目录内工作——越界访问在 OS 层被拒绝；
- 授权可设**到期时间**，到期自动从 MCP 消失并锁定远端账户。

核心思路：**授权即边界**。真实访问控制由服务器上的 POSIX ACL 执行，平台只负责供给与回收。

## 快速开始

```bash
# 服务端（任一台 Linux 主机）
./run.sh            # 生成 .env → 构建单二进制 → 启动；随机管理员密码写入 data/admin-password.txt
```

浏览器打开 `http://localhost:8080/login` 登录：添加服务器 → 建/接入账户（真实 OS 用户 + 逐目录 ACL）→ 打开「暴露」开关 → 可选设置到期。

```bash
# agent 端（一次调用，缓存到 agent 上下文）
curl -s -H "Authorization: Bearer $SAL_MCP_TOKEN" \
     -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
     -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_exposed_accounts","arguments":{}}}' \
     http://sal-host:8080/mcp

# 或在任何支持 MCP 的 agent 里挂 streamable HTTP 端点，随后在授权目录内工作：
sshpass -p '<password>' ssh coder1@10.0.0.5 'cd /data/repo && <任意命令>'
```

驱动 Claude Code 是其中一种用法：在授权目录里 `claude -p "任务"` 即可——平台不关心目录里跑什么。

### 或用命令行管理

同一二进制内置 `ctl` 子命令，直接管理**运行中**的服务（走 REST API，无需打开 UI）：

```bash
export SAL_SERVER_URL=http://127.0.0.1:18080   # 缺省从 SAL_LISTEN_ADDR 推导（http://127.0.0.1:8080）
export SAL_ADMIN_PASSWORD=...                   # 管理员密码
export SAL_MCP_TOKEN=...                        # 仅 exposed 子命令需要

server-agent-link ctl servers                                       # 列出服务器
server-agent-link ctl server-add dev1 10.0.0.5 22 root prod         # 添加（tag: prod）
server-agent-link ctl server-test <id>                              # 探测 root/sudo/plain 分级
server-agent-link ctl account-add <id> coder1 '密码' '/data/repo=rw,/logs=ro' '2026-12-31T23:59:59+08:00'
server-agent-link ctl account-expose <account-id> on                # 暴露开关
server-agent-link ctl exposed                                       # agent 视角（密码打码）
```

`server-agent-link ctl` 打印全部 14 个命令。所有写操作与 Web UI 走同一 API 与审计。完整参考见[使用说明](docs/使用说明.md)的「命令行管理（CLI）」章节。

## 特性

- **真实供给**：`useradd` / `chpasswd` / `setfacl` / `userdel` 真实执行，非 root 管理账户自动 `sudo -n` 提权
- **逐目录 ACL**：`rw`/`ro` 授权含默认 ACL（新文件自动继承）；删户前逐目录撤销，无孤儿权限
- **到期回收**：`expires_at` → MCP 立即停止暴露 → 远端账户锁定（不删数据，续期后「重新建户」恢复）
- **MCP 目录**：`list_exposed_accounts` 只返回已暴露、未到期、服务器启用的账户凭据
- **安全默认**：凭据 AES-256-GCM 落库、argon2id 管理员、HMAC 会话 + CSRF + 登录限流、SSH TOFU 指纹、操作审计日志
- **部署极简**：单静态二进制（纯 Go，无 cgo）、SQLite 版本化迁移自动升级、内嵌 Web UI、systemd 单元与备份脚本开箱即用

## 文档

- [使用说明](docs/使用说明.md) · [User Guide](docs/USER_GUIDE_EN.md)——环境变量、API 参考、MCP 接入、安全模型、备份恢复、常见故障
- [deploy/](deploy/)——systemd 单元模板与备份脚本
- [.env.example](.env.example)——全部配置项注释


## 测试

```bash
go test ./...                                   # 单元测试
go test -tags integration ./internal/sshx/      # 真实 sshd 集成测试（需 docker）
```

## License

[MIT](LICENSE)
