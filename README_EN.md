# ServerAgentLink

**A single static binary. Zero external dependencies. Copy and run.** Securely expose directories across multiple servers to your local agents: OS account provisioning + per-directory ACL grants + an MCP credential directory — safe permission management for agents working across a server fleet.

> 中文版本：[README.md](README.md)

A local assistant agent often needs to work on many servers at once (read/write code repos, inspect logs, edit configs). ServerAgentLink is the **permission foundation** for that workflow:

- **For humans** (Web UI): register servers → provision real OS accounts on them → grant per-directory read-only/read-write ACLs → decide which accounts are exposed to agents, and when they expire.
- **For agents** (MCP): one read-only tool, `list_exposed_accounts`. A single call returns every authorized "server + account + directory list"; the agent then works **only inside** granted directories — anything beyond the boundary is rejected at the OS level.

The core idea is **authorization as the boundary**: agents never run around with a root password. They receive a set of least-privilege OS accounts; real access control is enforced by POSIX ACLs on the servers, while the platform only handles provisioning and revocation.

It does **not** act as a task broker (no agent orchestration) and does **not** manage Anthropic API keys — orthogonal to orchestration ADEs like orca: agents acquire credentials and authorization here first, then get orchestrated wherever.

## Onboard an agent in 5 minutes

```bash
# 1) Fetch accounts (once, cache into agent context): which accounts exist on
#    which servers, and which directories are readable/writable
curl -s -H "Authorization: Bearer $SAL_MCP_TOKEN" \
     -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
     -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_exposed_accounts","arguments":{}}}' \
     http://sal-host:8080/mcp

# 2) Work inside granted directories (any agent workflow: coding, log inspection, config changes…)
sshpass -p '<password>' ssh -o StrictHostKeyChecking=accept-new \
  coder1@10.0.0.5 -p 22 \
  'cd /data/repo && <any command>'
```

Or attach the streamable HTTP endpoint `http://sal-host:8080/mcp` in any MCP-capable agent, with header `Authorization: Bearer <SAL_MCP_TOKEN>`.

Driving Claude Code is one example: the agent sshes to the target server and runs `claude -p "<task>" --dangerously-skip-permissions` inside a granted directory — Claude Code is just one use of an authorized directory; the platform doesn't care what the agent runs there.

All admin operations happen in the Web UI: add a server (root credentials) → create accounts (real OS users + per-directory ACLs) → flip the "expose" switch. Zero configuration on the agent side.

## Architecture

```
┌─────────────┐        ┌──────────────────────────────────────────┐
│   Browser    │  HTTP  │  ServerAgentLink (single Go binary)      │
│  (Web UI)    ├───────►│                                          │
└─────────────┘        │  Web UI (embedded templates) → REST API  │
                       │        │                  │               │
┌─────────────┐        │        ▼                  ▼               │
│  Local agent │  MCP   │  MCP service (streamable HTTP, Bearer)   │
│ (coclaw/     ├───────►│   list_exposed_accounts (read-only)      │
│  hermes/any) │        │        │                                  │
└─────────────┘        │        ▼                                  │
                       │  SSH executor (root creds: useradd/      │
                       │  chpasswd/setfacl/usermod)                │
                       │        │                                  │
                       │  SQLite store (AES-256-GCM encrypted     │
                       │  credentials, user_version migrations)   │
                       │        │                                  │
                       │  Expiry reaper (10-min scan: locks       │
                       │  expired OS accounts)                     │
                       └───────────────┬──────────────────────────┘
                                       │ SSH (root)
                       ┌───────────────┴──────────────┐
                       │  Server A        Server B …   │
                       │  (OS accounts + per-dir ACL)  │
                       └──────────────────────────────┘
```

- **Web UI / REST API**: add a server and "test connection" to verify host/credentials/fingerprint; create/delete accounts; grant or change per-directory permissions (ACLs revoked on account deletion); change passwords; toggle "coding / expose" switches; set account expiry. The homepage summarizes everything currently exposed to agents (expired accounts disappear automatically).
- **MCP service**: the `list_exposed_accounts` tool returns exposed, non-expired accounts with `host / ssh_port / username / password / directories`.
- **SSH executor**: runs real commands on servers with root credentials — `useradd`, `chpasswd`, `setfacl`, `userdel`, `usermod -L` (expiry lock); non-root sudo accounts automatically escalate via `sudo -n`.
- **Expiry reaper**: scans every 10 minutes; expired accounts disappear from MCP exposure immediately, then their remote OS accounts get locked (password locked + nologin, data preserved; admins can delete, or renew + re-provision to restore).
- **SQLite store**: account passwords encrypted at rest with AES-256-GCM; admin password hashed with argon2id; `PRAGMA user_version` versioned migrations — upgrades never corrupt the database.

## Security model

The agent's actual permission boundary on each server is formed by four layers:

1. **OS account isolation**: every exposed account is a dedicated OS user — no shared credentials with root or anyone else; process-level isolation (home, umask, shell) comes for free.
2. **Per-directory ACLs**: `setfacl` grants `rw`/`ro` per directory (including default ACLs, inherited by new files); every path outside the whitelist is rejected under the server's existing permission semantics.
3. **Platform-side switches**: `exposed_to_agent` controls whether credentials appear in the MCP directory; `expires_at` controls when exposure ends — gone from MCP immediately, remote account locked shortly after.
4. **Platform security itself**: AES-256-GCM encrypted credentials at rest, static Bearer on MCP, admin argon2id + HMAC sessions + CSRF + login rate limiting, SSH TOFU fingerprints, audit logging.

## Environment variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `SAL_LISTEN_ADDR` | No | `:8080` | Listen address |
| `SAL_DATA_DIR` | No | `./data` | Data directory (SQLite + master.key) |
| `SAL_MASTER_KEY` | No | auto-generated | 32-byte hex master key; generated to `$SAL_DATA_DIR/master.key` if absent |
| `SAL_MCP_TOKEN` | **Yes** | — | Static Bearer token for the MCP endpoint |
| `SAL_ADMIN_USER` | No | `admin` | Admin username |
| `SAL_ADMIN_PASSWORD` | No | auto-generated | Admin password on first run; if absent, a random one is written to `$SAL_DATA_DIR/admin-password.txt` (0600) |
| `SAL_TLS_CERT` | No | — | TLS certificate path (pair with `SAL_TLS_KEY`) |
| `SAL_TLS_KEY` | No | — | TLS private key path (pair with `SAL_TLS_CERT`) |
| `SAL_ENV_FILE` | No | `.env` | Override the `.env` config file path |

> All variables can come from real environment variables or a `.env` file in the project root (`cp .env.example .env` and edit); **real environment variables take precedence over `.env`**. See [.env.example](.env.example) for full annotations.

## Build and run

Prerequisite: **Go 1.26+** (`go build` reads the version from go.mod).

### One command (recommended)

```bash
./run.sh
```

The script generates `.env` if missing (filling `SAL_MCP_TOKEN` with a random strong value) → builds the single binary → starts it. If `SAL_ADMIN_PASSWORD` is unset on first run, a random admin password is written to `data/admin-password.txt` (0600); use it to log in.

### Manual build and run

```bash
# 1) Configure (optional): copy the template and edit SAL_MCP_TOKEN / SAL_LISTEN_ADDR etc.
cp .env.example .env

# 2) Build the single binary
go build -o server-agent-link ./cmd/server-agent-link

# 3) Run (reads .env automatically; real environment variables win)
./server-agent-link
```

Then open `http://localhost:8080/login` and sign in. For production, set `SAL_TLS_CERT`/`SAL_TLS_KEY` to enable HTTPS.

> To deploy on a machine without Go, cross-compile elsewhere and copy the binary, e.g.
> `GOOS=linux GOARCH=amd64 go build -o server-agent-link ./cmd/server-agent-link`.

## ACL prerequisites

The permission backend is `acl` (the only supported backend). Target servers must have:

1. The `acl` package installed (Debian/Ubuntu: `apt-get install acl`).
2. The filesystem holding granted directories mounted with the `acl` option (`mount -o remount,acl /`, or add `acl` in `/etc/fstab`).

Otherwise `setfacl` fails and the account is marked `error`.

## MCP response example

`list_exposed_accounts` only returns accounts with `exposed_to_agent=1` on `enabled=1` servers that are **not expired**:

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

## Security and operations

- Account passwords and server root passwords are encrypted at rest with **AES-256-GCM** (nonce‖ciphertext); the key comes from `SAL_MASTER_KEY` (or the `master.key` file, 0600). **Back up the db and master.key together**: `./deploy/backup.sh` does it in one command.
- Admin passwords are hashed with **argon2id**, never stored in plaintext.
- Sessions are **HMAC-SHA256 signed cookies** (`SameSite=Strict`, `HttpOnly`, `Secure` when TLS is on), login rate-limited to 5 attempts/min/IP (atomic counting, `X-Forwarded-For` is not trusted).
- State-changing endpoints enforce **double-submit CSRF** (`sal_csrf` cookie + `X-CSRF-Token` header).
- First SSH connections use **TOFU** host key pinning (SHA256 fingerprint) to prevent MITM; after host migration/reinstall, reset via `reset_host_key`.
- The MCP endpoint returns plaintext credentials — protect it with a strong `SAL_MCP_TOKEN` and expose it only on trusted/internal networks.
- Server logs and operation audits (`audit user=... action=...`) go to stdout; under systemd, search with `journalctl -t server-agent-link`.
- For production, see the systemd unit template in [deploy/server-agent-link.service](deploy/server-agent-link.service) (least-privilege hardening + auto-restart).

Full usage and operations guide: [docs/使用说明.md](docs/使用说明.md) (Chinese).

## Testing

```bash
go test ./...                                   # unit tests
go test -tags integration ./internal/sshx/      # optional: needs a docker sshd (see integration_test.go)
```

## Roadmap

### Done ✅

- [x] Single Go binary + embedded SQLite (pure Go, no external database/runtime; `user_version` versioned migrations, legacy databases upgrade automatically)
- [x] Web UI (console style): servers / accounts / per-directory permission management
- [x] Server connectivity test (SSH dial + TOFU host fingerprint pinning)
- [x] Real account provisioning/deletion/password change/permission change (ACL backend; non-root auto `sudo -n` escalation; per-directory ACLs revoked before deletion)
- [x] Account "coding / expose" switches + homepage "exposed to agents" overview
- [x] **Automatic account expiry** (`expires_at` → MCP exposure stops → OS account locked; renewable to restore)
- [x] MCP service `list_exposed_accounts` (streamable HTTP + Bearer auth)
- [x] Security: AES-256-GCM credential encryption, argon2id, HMAC sessions, CSRF, login rate limiting
- [x] Server-side logs + operation audit (`audit` lines, stdout/journald)
- [x] Master key persistence (master.key) + `.env` config + `run.sh` one-command start
- [x] Deployment assets: systemd unit template + backup script (`deploy/`)

### Planned 🚧

- [ ] **Multi-cloud ingestion (Alibaba Cloud / Volcengine etc.)**: pull instance lists via cloud vendor OpenAPIs and import servers; bulk provisioning and directory grants. Suggested path: read-only discovery → admin-confirmed import → gradual automation
- [ ] Account password rotation and scheduled password changes
- [ ] Server groups and tags
- [ ] Monitoring and alerting (account error, connection failures → webhook notifications)

### Explicitly out of scope (keeping the footprint small)

- Multi-admin / RBAC (single admin + audit logs already cover self-hosted intranet use)
- Agent orchestration / worktree fan-out / harness presets (orca territory)
- Anthropic API key management / token cost governance
- Kubernetes / containerized platforms (a single static binary + systemd is enough)

> Planning note: for multi-cloud, first abstract a unified "credentials + instance" model (host/port/login user/key source), then adapt each cloud SDK — the current SSH credential + ACL model is a sufficient foundation; cloud platforms only "discover instances and inject credentials", while authorization reuses the existing `useradd/setfacl` pipeline.
