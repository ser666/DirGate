# DirGate User Guide

> Complete operations manual for administrators. For a quick overview see the [README](../README.md).

[English](../README.md) · English Guide · [中文说明](../README_ZH.md) · [中文指南](使用说明.md)

DirGate securely exposes **directories across multiple servers to your local agents**: register servers on the platform, provision (or attach) real OS accounts, grant per-directory read-only / read-write ACLs, and serve the exposed credentials to any MCP-capable personal agent (coclaw, hermes, etc.). Agents then work **only inside** granted directories — coding, inspecting logs, editing configs — while anything beyond the boundary is rejected at the OS level.

**Authorization is the boundary**: agents receive a set of least-privilege OS accounts, never root; real access control is enforced by POSIX ACLs on the servers, and the platform only handles provisioning and revocation. The platform itself is **not** a task broker and does **not** manage Anthropic API keys — driving Claude Code (`claude -p "<task>"` inside a granted directory) is just one use among many; the platform neither knows nor limits what runs there.

---

## Table of contents

1. [Concepts & architecture](#1-concepts--architecture)
2. [Installation & deployment](#2-installation--deployment)
3. [CLI management](#3-cli-management)
4. [Environment variables](#4-environment-variables)
5. [First run](#5-first-run)
6. [Web UI workflow](#6-web-ui-workflow)
7. [Access-mode tiers (root / sudo / plain)](#7-access-mode-tiers-root--sudo--plain)
8. [Account expiry & reclamation](#8-account-expiry--reclamation)
9. [REST API reference](#9-rest-api-reference)
10. [MCP onboarding (agent side)](#10-mcp-onboarding-agent-side)
11. [Security model & operations](#11-security-model--operations)
12. [Backup & restore](#12-backup--restore)
13. [Troubleshooting](#13-troubleshooting)
14. [Testing](#14-testing)

---

## 1. Concepts & architecture

### 1.1 Core concepts

| Concept | Description |
|---|---|
| **Server** | A target host manageable over SSH. Registration takes host, SSH port, and an admin account (username + password). |
| **Admin account** | The account used to run provisioning commands on the server. Comes in three capability tiers: `root` / `sudo` / `plain` (see §6). |
| **Account** | A real OS user on a server — either provisioned by the platform (root/sudo mode) or attached (plain mode). |
| **Directory permission** | An `rw` (read-write) or `ro` (read-only) grant for one account on one directory, enforced via POSIX ACL including default ACLs (new files inherit automatically). |
| **Expose** | Per-account switch. Only exposed accounts appear in the MCP directory. |
| **Expiry** | Per-account RFC3339 timestamp. After expiry the credential disappears from MCP immediately and the remote account is locked (or ACL-revoked in plain mode). |
| **MCP directory** | One read-only MCP tool, `list_exposed_accounts`, returning all accounts that are exposed, non-expired, and on enabled servers. |

### 1.2 Architecture

```
┌─────────────┐        ┌──────────────────────────────────────────┐
│   Browser    │  HTTP  │  DirGate (single Go binary)      │
│  (Web UI)    ├───────►│                                          │
└─────────────┘        │  Web UI (embedded templates) → REST API  │
                       │        │                  │               │
┌─────────────┐        │        ▼                  ▼               │
│  Local agent │  MCP   │  MCP service (streamable HTTP, Bearer)   │
│ (coclaw/     ├───────►│   list_exposed_accounts (read-only)      │
│  hermes/any) │        │        │                                  │
└─────────────┘        │        ▼                                  │
                       │  SSH executor (useradd/chpasswd/setfacl/ │
                       │  userdel/usermod, routed by access_mode) │
                       │        │                                  │
                       │  SQLite store (AES-256-GCM encrypted     │
                       │  credentials, user_version migrations)   │
                       │        │                                  │
                       │  Expiry reaper (10-minute scan)          │
                       └───────────────┬──────────────────────────┘
                                       │ SSH
                       ┌───────────────┴──────────────┐
                       │  Server A        Server B …   │
                       │  (OS accounts + per-dir ACL)  │
                       └──────────────────────────────┘
```

### 1.3 Security model (four boundary layers)

1. **OS account isolation**: every exposed account is a dedicated OS user — no shared credentials with root or anyone else; process-level isolation (home, umask, shell) comes for free.
2. **Per-directory ACLs**: `setfacl` grants `rw`/`ro` per directory including default ACLs; everything outside the whitelist is rejected under the server's existing permission semantics.
3. **Platform-side switches**: `exposed_to_agent` decides whether credentials appear in the MCP directory; `expires_at` decides when exposure ends.
4. **Platform security itself**: AES-256-GCM credentials at rest, static Bearer on MCP, argon2id admin hash + HMAC sessions + CSRF + login rate limiting, SSH TOFU fingerprints, audit logging.

---

## 2. Installation & deployment

### 2.1 Prebuilt binaries (no Go needed)

Download `dirgate-<os>-<arch>` from [Releases](https://github.com/ser666/DirGate/releases), `chmod +x`, provide a `.env` (copy from `.env.example`), run. Binaries are static — copy them to any machine of the same OS/arch.

### 2.2 One command (builds from source)

```bash
./run.sh
```

The script generates `.env` if missing (filling `DG_MCP_TOKEN` with a random strong value), builds the single binary, and starts it.

### 2.3 Manual build & run

```bash
cp .env.example .env            # edit as needed; at minimum set DG_MCP_TOKEN
go build -o dirgate ./cmd/dirgate
./dirgate             # reads .env; real environment variables win
```

### 2.4 Cross-compile for machines without Go

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o dirgate ./cmd/dirgate
# copy the binary to the target machine, provide .env, run
```

### 2.5 systemd production deployment

The unit template lives at [deploy/dirgate.service](../deploy/dirgate.service):

```bash
cp dirgate /usr/local/bin/
useradd -r -s /usr/sbin/nologin sal
mkdir -p /var/lib/dirgate && chown sal:sal /var/lib/dirgate
cp deploy/dirgate.service /etc/systemd/system/
# put secrets (DG_MCP_TOKEN etc.) in /etc/dirgate.env (chmod 600)
systemctl daemon-reload && systemctl enable --now dirgate
```

The unit ships with auto-restart, `ProtectSystem=strict` hardening, and journald logging. Audit trail:

```bash
journalctl -t dirgate -g audit
```

### 2.6 Target server prerequisites

Permission enforcement uses POSIX ACL. Target servers need:

1. The `acl` package: Debian/Ubuntu `apt-get install acl`, RHEL/CentOS `yum install acl`, Alpine `apk add acl`.
2. The filesystem holding granted directories mounted with `acl` (`mount -o remount,acl /`, or `acl` in `/etc/fstab`).

Otherwise `setfacl` fails and the account is marked `error` (reason shown inline on the detail page).

### 2.7 Port notes

Some corporate host firewalls DROP common web ports such as 8080/8081 (loopback included). If the service is listening but the browser can't reach it, switch to a high port (e.g. `DG_LISTEN_ADDR=:18080`) before debugging the firewall.

---

## 3. CLI management

The same binary ships a `ctl` subcommand — manage a **running** service over its REST API, no config edits, no local data directory:

```bash
# credentials via environment (keep the password out of scripts)
export DG_SERVER_URL=http://127.0.0.1:18080   # default: derived from DG_LISTEN_ADDR
export DG_ADMIN_PASSWORD=...                   # required
export DG_MCP_TOKEN=...                        # only for `exposed`

dirgate ctl servers
dirgate ctl server-add dev1 10.0.0.5 'root-password' 22 root prod
dirgate ctl server-test <server-id>          # connectivity + root/sudo/plain probe
dirgate ctl server-enable <server-id> off    # pull a whole server out of MCP
dirgate ctl accounts <server-id>
dirgate ctl account-add <server-id> coder1 'pass' '/data/repo=rw,/logs=ro' '2026-12-31T23:59:59+08:00'
dirgate ctl account-expose <account-id> on
dirgate ctl account-expiry <account-id> never
dirgate ctl account-perms <account-id> '/data/repo=rw'
dirgate ctl account-passwd <account-id> 'newpass'
dirgate ctl account-provision <account-id>
dirgate ctl account-del <account-id>
dirgate ctl exposed                          # agent's view of the MCP directory (passwords masked)
```

Bare `dirgate ctl` prints all commands. Writes go through the same API and audit trail as the Web UI.

## 4. Environment variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `DG_LISTEN_ADDR` | No | `:8080` | Listen address |
| `DG_DATA_DIR` | No | `./data` | Data directory (SQLite + `master.key` + `admin-password.txt`) |
| `DG_MASTER_KEY` | No | auto-generated | 32-byte hex master key encrypting all stored credentials. **Must never change once data exists** (see §10.1) |
| `DG_MCP_TOKEN` | **Yes** | — | Static Bearer token for the MCP endpoint |
| `DG_ADMIN_USER` | No | `admin` | Admin username |
| `DG_ADMIN_PASSWORD` | No | auto-generated | Admin password on first run; if absent a random one is written to `$DG_DATA_DIR/admin-password.txt` (0600) |
| `DG_TLS_CERT` | No | — | TLS certificate path (pair with `DG_TLS_KEY`) |
| `DG_TLS_KEY` | No | — | TLS private key path (pair with `DG_TLS_CERT`) |
| `DG_ENV_FILE` | No | `.env` | Override the `.env` path |

> Real environment variables take precedence over `.env`. With TLS set the service listens on HTTPS and session cookies get `Secure`; without it, plaintext HTTP — for production use TLS or a reverse proxy, since admin logins and credentials traverse this channel.

---

## 5. First run

1. If `DG_ADMIN_PASSWORD` is unset, a random admin password is written to `$DG_DATA_DIR/admin-password.txt` (0600) — never printed to logs/stdout.
2. If `DG_MASTER_KEY` is unset, a 32-byte random master key is generated at `$DG_DATA_DIR/master.key`.
3. Open `http://<host>:<port>/login`, sign in with the admin credentials.
4. Use the **EN/中文** button in the top bar to switch UI language (stored in browser localStorage).

Master key protection: the program refuses anything that could make ciphertext undecryptable — invalid `DG_MASTER_KEY` format aborts startup; a corrupt-length `master.key` is never overwritten; "keyfile missing but database exists" errors out and demands the original key.

---

## 6. Web UI workflow

1. **Sign in** at `/login`.
2. **Add a server**: fill name, host, SSH port (default 22), admin username (default root), password.
3. **Test Connection**: performs a real SSH dial verifying reachability, credentials, and host fingerprint; on success it **pins the fingerprint and probes the access-mode tier** (`root`/`sudo`/`plain`, shown next to status). After a host migration/reinstall the fingerprint changes and tests report `host key mismatch` — reset via "Reset host key" or by editing `host`.
4. **Create an account**: on the server detail page fill username, password, directory permissions (`path=mode` comma-separated, e.g. `/data/a=rw,/data/b=ro`), optional expiry. The platform really runs `useradd` + `chpasswd` + `setfacl` over SSH. If the username already exists its password is reset and permissions applied (idempotent — equivalent to taking over an existing account). In plain mode only the admin account itself can be attached (see §6).
5. **View accounts**: the table lists status (active / error / pending / locked), directory permissions, expiry. Errors show the remote failure reason inline.
6. **Toggle "Expose"**: per-account switch, saves immediately.
7. **Homepage exposure overview**: "Accounts exposed to agents" aggregates across servers what agents can actually reach (**no passwords shown**). Expired accounts disappear from here and from MCP automatically.
8. **Edit permissions**: per-account permission editor pushes real ACL changes, including revocation of removed directories.
9. **Change password**: resets the OS user's password and updates the encrypted store. Not supported in plain mode (the API explains; run `passwd` on the server first).
10. **Set expiry**: RFC3339 timestamp per account (empty = never). After expiry the account leaves MCP immediately; the reaper locks the remote side shortly after.
11. **Re-provision**: re-runs password setup and ACLs for an existing OS user (idempotent), repairing `error` states; on a `locked` account it unlocks and restores.
12. **Delete account**: revokes per-directory ACLs first, then `userdel -r`; remote failures keep the record for retry. Plain mode only revokes ACLs and deletes the platform record — the OS user is untouched.
13. **Delete server**: deletes all its accounts remotely first (database only when all succeed); failures keep everything for retry.

---

## 7. Access-mode tiers (root / sudo / plain)

"Test Connection" probes the admin account's real capabilities; the detected `access_mode` determines the provisioning path:

| Mode | Detection | Create users | Directory grants | Expiry lock | Delete | Change password |
|---|---|---|---|---|---|---|
| `root` | uid 0 | ✅ useradd | ✅ any directory | ✅ usermod -L + nologin | ✅ userdel -r (ACLs revoked first) | ✅ |
| `sudo` | passwordless sudo (NOPASSWD) | ✅ via sudo | ✅ any directory | ✅ same | ✅ same | ✅ |
| `plain` | regular account, no privileges | ❌ attach only | ✅ owned directories only | ✅ revoke all granted ACLs | ✅ revoke ACLs + delete record (**OS user kept**) | ❌ run `passwd` on the server |

**Why plain mode exists**: on shared servers you often hold only a regular dev account with no root. DirGate still works — attach your own account, ACL-isolate directories you own, and serve credentials to your agent via MCP. The kernel rejects anything beyond owned directories (`setfacl` on others' directories simply fails), a natural backstop.

Notes:
- In plain mode the account username must equal the admin account; anything else gets HTTP 400.
- Password changes in plain mode require running `passwd` on the server, then deleting and re-attaching the account record with the new password.
- On root/sudo servers "Re-provision" also reverses expiry locks (usermod -U + restore bash).

---

## 8. Account expiry & reclamation

### 7.1 How it works

1. Set `expires_at` on an account (RFC3339, e.g. `2026-12-31T23:59:59+08:00`).
2. **Immediate**: expired accounts vanish from MCP `list_exposed_accounts` and the homepage overview (filtered on every call).
3. **Background reclamation**: the reaper scans every 10 minutes for expired, unlocked accounts:
   - root/sudo servers: `usermod -L` locks the password + `/sbin/nologin` locks the shell (**data preserved**);
   - plain servers: `setfacl -x` revokes the account's own entries on all granted directories (including default ACL entries — isolation equivalent).
4. **After locking**: the detail page shows a "Locked" badge. Either delete the account, or raise `expires_at` and hit "Re-provision" to restore (unlock + restore shell + re-apply ACLs).
5. Lock failures (server unreachable etc.) mark the account `error` with the reason and retry on the next scan.

### 7.2 Typical usage

- **Temporary grants**: provision an account for a contractor with a 7-day expiry — it dies automatically, no manual cleanup.
- **Approval means expiry**: whenever you manually approve an exposure, set an expiry in the same breath — making auto-revocation the default habit.

---

## 9. REST API reference

All `/api/*` (except `/api/login`, `/api/logout`) requires a session (`dg_session` cookie). State-changing methods (POST/PUT/DELETE) additionally require CSRF: send the `dg_csrf` cookie value back in the `X-CSRF-Token` header (the built-in frontend does this automatically; scripts must maintain it themselves).

### Auth

| Method / path | Description |
|---|---|
| `POST /api/login` | `{"username","password"}` → sets session + csrf cookies |
| `POST /api/logout` | clears session + csrf cookies |

### Servers

| Method / path | Body | Description |
|---|---|---|
| `GET /api/servers` | — | list (no credentials; includes `access_mode`, `tag`) |
| `POST /api/servers` | `{"name","host","ssh_port","root_user","root_password","tag"?}` | add |
| `GET /api/servers/{id}` | — | detail |
| `POST /api/servers/{id}/test` | — | connectivity test + tier probe, returns `{"connected":bool,"host_key","access_mode"}`; pins fingerprint and records verification time on success |
| `PUT /api/servers/{id}` | any subset; `enabled:*bool`, `reset_host_key:true` or changing `host` clears the pinned fingerprint | update |
| `DELETE /api/servers/{id}` | — | delete (deletes all accounts remotely first; database only when all succeed) |

> Disabling a server (`"enabled": false`) removes all its accounts from the MCP directory in one move.

### Accounts

| Method / path | Body | Description |
|---|---|---|
| `GET /api/servers/{id}/accounts` | — | list accounts (with per-directory permissions, `expires_at`) |
| `POST /api/servers/{id}/accounts` | `{"username","password","exposed_to_agent","expires_at"?,"permissions":[{"path","mode"}]}` | create and provision for real |
| `POST /api/accounts/{id}/provision` | — | re-provision (idempotent; unlocks locked accounts) |
| `PUT /api/accounts/{id}` | `{"exposed_to_agent"?, "expires_at"?}` | toggle flags / set expiry |
| `PUT /api/accounts/{id}/password` | `{"password"}` | reset the OS user's password and update the encrypted store (400 in plain mode) |
| `DELETE /api/accounts/{id}` | — | delete (revokes ACLs per directory first, then the OS user; plain mode revokes ACLs and deletes the record only) |
| `GET /api/accounts/{id}/permissions` | — | list permissions |
| `PUT /api/accounts/{id}/permissions` | `[{"path","mode"}]` | overwrite permissions (revokes removed directories' ACLs) |

Field values:
- `mode`: `rw` (read-write) | `ro` (read-only).
- account `status`: `pending` | `active` | `error` | `locked` (expiry-locked).
- `expires_at`: RFC3339 timestamp or empty string (never). Past timestamps are allowed (treated as immediately expired).

---

## 10. MCP onboarding (agent side)

The MCP service is **streamable HTTP** at `/mcp`, static Bearer auth, one read-only tool.

### 10.1 Mount directly in your MCP client config

Paste this into your MCP client config file (Claude Code `.mcp.json`, Claude Desktop `claude_desktop_config.json`, etc. — key names vary slightly per client):

```json
{
  "mcpServers": {
    "dirgate": {
      "url": "http://127.0.0.1:18080/mcp",
      "headers": {
        "Authorization": "Bearer <YOUR_DG_MCP_TOKEN>"
      }
    }
  }
}
```

> `<YOUR_DG_MCP_TOKEN>` is in the server's `.env`; point `url` at the host running DirGate. For stdio-only clients, bridge with a community tool: `npx mcp-remote http://dirgate-host:18080/mcp --header "Authorization: Bearer <token>"`.

```json
{
  "mcpServers": {
    "dirgate": {
      "type": "streamableHttp",
      "url": "http://dirgate-host:18080/mcp",
      "headers": { "Authorization": "Bearer <DG_MCP_TOKEN>" }
    }
  }
}
```

### 10.2 curl smoke test

```bash
curl -H "Authorization: Bearer <DG_MCP_TOKEN>" \
     -H "Content-Type: application/json" \
     -H "Accept: application/json, text/event-stream" \
     -X POST \
     -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_exposed_accounts","arguments":{}}}' \
     http://dirgate-host:18080/mcp
```

Response (only accounts with `exposed_to_agent=1` on `enabled=1` servers that are **not expired**):

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "content": [{
      "type": "text",
      "text": "{\"revision\":\"2026-11-15T04:00:00Z\",\"accounts\":[{\"server_id\":\"...\",\"server_name\":\"dev1\",\"host\":\"10.0.0.5\",\"ssh_port\":22,\"username\":\"coder1\",\"password\":\"...\",\"tag\":\"prod\",\"expires_at\":\"\",\"directories\":[{\"path\":\"/data/repo\",\"mode\":\"rw\"}]}]}"
    }]
  }
}
```

### 10.3 Agent conventions

- Work **only inside** the listed `directories`. Mind the grant granularity: it covers the **whole subtree** — `ro` (ACL `rx`) allows reading, traversing, and executing files already present; `rw` allows writes. There is no per-subpath exclusion, so check a subtree's contents before granting.
- Route across servers by `tag` (prod / test / project name) or `server_name + host`; each account's password is independent.
- **Credential caching & revision**: every call returns `revision` (a global version of the exposed directory). Save it when caching credentials; on the next call, a changed revision means a password/flag/expiry changed — refresh your local cache before SSHing.
- **Self-aware expiry**: `expires_at` ships with each account (empty = never). Agents can judge their usable window and avoid retrying dead credentials.
- **OS-layer lag**: after expiry the MCP directory updates instantly, but the remote OS lock runs on the background reaper (10-minute scan) — old credentials may still log in for up to 10 minutes. This is by design.

### 10.4 Access audit

Every MCP credential-directory fetch writes an audit line (`audit user=agent ip=<source-IP> action=mcp.POST`). The platform can audit **who fetched credentials**; an agent's actual behavior on the server (commands run, files read) depends on the target host's own sshd logging — enable `sshd LogLevel VERBOSE` with syslog collection there.

> The MCP endpoint returns **plaintext credentials** — protect it with a strong `DG_MCP_TOKEN` and expose it only on trusted networks. On client machines, make sure the service address is in `no_proxy` (corporate proxies hijack 127.0.0.1 / internal requests).

---

## 11. Security model & operations

### 11.1 Master key (handle with care)

- All root/account passwords are encrypted at rest with **AES-256-GCM**; the key comes from `DG_MASTER_KEY` or `$DG_DATA_DIR/master.key`.
- **Changing the key source / losing the key = permanently losing every stored password.** Guards: invalid format aborts startup; wrong-length keyfile is never overwritten; "keyfile missing but database exists" demands the original key.
- For production, keep the master key in a secrets manager and inject it explicitly.

### 11.2 SSH host fingerprints (TOFU)

- The first successful connection records the target's SHA256 fingerprint; every later connection verifies it, and a mismatch is rejected (MITM protection).
- After a host migration/reinstall: `PUT /api/servers/{id}` with `"reset_host_key": true`, or edit the `host` field (clears the fingerprint automatically).

### 11.3 SSH escalation (sudo)

- The platform SSHes in as the registered admin account to run `useradd`/`chpasswd`/`setfacl`/`userdel`.
- Non-root (uid≠0) automatically escalates with `sudo -n`, requiring `NOPASSWD: ALL` in sudoers — otherwise it fails immediately (account marked `error`).
- True root skips sudo; plain mode uses no privileged operations at all.

### 11.4 Login & CSRF

- Admin passwords are argon2id-hashed, never stored in plaintext.
- Sessions are HMAC-SHA256-signed cookies (`HttpOnly`, `SameSite=Strict`, `Secure` under TLS).
- Login rate limiting: 5 attempts/min/IP (atomic counting, `X-Forwarded-For` is not trusted).
- State-changing endpoints enforce double-submit CSRF.

### 11.5 Audit

State-changing operations write one structured line to stdout (journald under systemd):

```
audit user=admin ip=10.0.0.2 action=account.create object=<id> <username>
```

Covered actions: `server.create/update/delete`, `account.create/update/delete/permissions/password/provision`, system reclamation `account.lock`, and MCP fetches `mcp.POST`. Retrieve with:

```bash
journalctl -t dirgate -g audit
```

---

## 12. Backup & restore

```bash
./deploy/backup.sh [data-dir] [output-dir]     # defaults: ./data ./backups
```

The backup contains the SQLite database + `master.key` (+ `admin-password.txt`). **They must be kept together**: losing `master.key` makes every stored ciphertext permanently undecryptable. With `sqlite3` installed the backup takes a consistent online snapshot; without it, files are copied directly (prefer a stopped window). Restore: unpack into the data directory and restart — schema migrations run automatically. Schedule via crontab and store copies off-host.

---

## 13. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Service listening but browser can't reach it | host firewall DROPs the port (8080 often blocked by corporate policy) | switch ports: `DG_LISTEN_ADDR=:18080` |
| Account status `error` | unreachable / wrong password / missing directory / no ACL package | fix, then "Re-provision" or call provision |
| `error` (permission denied) | admin account is non-root without passwordless sudo | configure `NOPASSWD: ALL`, use real root, or switch to plain mode |
| `host key mismatch` | target fingerprint changed | `reset_host_key` or edit `host` |
| Plain mode rejects a different username (400) | attach-only allows the admin account itself | only attach the admin account; use root/sudo mode for multiple accounts |
| Plain mode password change returns 400 | no privilege to chpasswd | run `passwd` on the server, then delete and re-attach the record |
| MCP call times out / code 000 | client went through a proxy | add the service address to `no_proxy` |
| `DG_MCP_TOKEN must be set` | token missing | set it and restart |
| Decryption failures (`message authentication failed`) | master key changed | restore the original `DG_MASTER_KEY` / `master.key` |
| Expired account still in MCP | stale cache | MCP filters on every call — just call again |

---

## 14. Testing

```bash
go test ./...                                   # unit tests (54+ cases)
go test -tags integration ./internal/sshx/      # real sshd integration tests (needs docker, see integration_test.go)
```

