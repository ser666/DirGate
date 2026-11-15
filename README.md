# DirGate

**A single static binary. Zero external dependencies. Copy and run.**
Securely expose directories across multiple servers to your local agents — OS account provisioning + per-directory ACL grants + an MCP credential directory.

English · [English Guide](docs/USER_GUIDE_EN.md) · [中文说明](README_ZH.md) · [中文指南](docs/使用说明.md)

## Why

Local assistant agents often work across many servers at once (read/write repos, inspect logs, edit configs) — but handing them a root password is unsafe and unauditable. DirGate is the **permission foundation** for that workflow:

- Admins register servers in a Web UI, provision **least-privilege OS accounts** for agents, and grant per-directory `rw`/`ro` ACLs;
- Agents fetch the full "server + account + directory list" through a single MCP tool, then work **only inside** granted directories — anything beyond the boundary is rejected at the OS level;
- Grants can carry an **expiry**: exposure vanishes from MCP automatically and the remote account gets locked.

The core idea: **authorization as the boundary**. Real access control is enforced by POSIX ACLs on the servers; the platform only handles provisioning and revocation.

## Quick start

Requires Go 1.26+ to build (the result is a single static binary — target machines need nothing but the binary and SSH access to the servers being managed; target servers need the `acl` package).

```bash
# Server side (any Linux host)
./run.sh            # generates .env → builds single binary → starts; random admin password in data/admin-password.txt
```

Open `http://localhost:8080/login`: add a server → create or attach accounts (real OS users + per-directory ACLs) → flip the "Expose" switch → optionally set an expiry.

```bash
# Agent side (one call, cache into agent context)
curl -s -H "Authorization: Bearer $SAL_MCP_TOKEN" \
     -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
     -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_exposed_accounts","arguments":{}}}' \
     http://sal-host:8080/mcp

# Or attach the streamable HTTP endpoint in any MCP-capable agent, then work inside granted directories:
sshpass -p '<password>' ssh coder1@10.0.0.5 'cd /data/repo && <any command>'
```

Driving Claude Code is one example: run `claude -p "<task>"` inside a granted directory — the platform doesn't care what runs there.

### Or manage it from the CLI

The same binary ships a `ctl` subcommand that drives a **running** service over its REST API — no UI, no config edits:

```bash
export SAL_SERVER_URL=http://127.0.0.1:18080   # or set SAL_LISTEN_ADDR; default http://127.0.0.1:8080
export SAL_ADMIN_PASSWORD=...                   # admin login
export SAL_MCP_TOKEN=...                        # only for `exposed`

dirgate ctl servers                                       # list servers
dirgate ctl server-add dev1 10.0.0.5 'root-password' 22 root prod         # add (tag: prod)
dirgate ctl server-test <id>                              # probe root/sudo/plain tier
dirgate ctl account-add <id> coder1 'pass' '/data/repo=rw,/logs=ro' '2026-12-31T23:59:59+08:00'
dirgate ctl account-expose <account-id> on                # exposure switch
dirgate ctl exposed                                       # agent's view (passwords masked)
```

`dirgate ctl` prints all 14 commands. Writes share the same API and audit trail as the Web UI. Full reference: the CLI section in the [Guide](docs/USER_GUIDE_EN.md).

## Features

- **Real provisioning**: `useradd` / `chpasswd` / `setfacl` / `userdel` executed for real; non-root admin accounts escalate via `sudo -n` automatically
- **Per-directory ACLs**: `rw`/`ro` grants include default ACLs (inherited by new files); ACLs revoked directory-by-directory before account deletion — no orphans
- **Expiry & reclamation**: `expires_at` → MCP exposure stops immediately → remote account locked (data preserved; renew + re-provision to restore)
- **MCP directory**: `list_exposed_accounts` returns only exposed, non-expired accounts on enabled servers
- **Secure defaults**: AES-256-GCM credentials at rest, argon2id admin hash, HMAC sessions + CSRF + login rate limiting, SSH TOFU fingerprints, operation audit log
- **Trivial deployment**: single static binary (pure Go, no cgo), SQLite with versioned auto-migrations, embedded Web UI, systemd unit and backup script included

## Documentation

- [Guide](docs/USER_GUIDE_EN.md) · [指南（中文）](docs/使用说明.md) — environment variables, API reference, MCP onboarding, security model, backup/restore, troubleshooting
- [deploy/](deploy/) — systemd unit template and backup script
- [.env.example](.env.example) — annotated configuration reference


## Testing

```bash
go test ./...                                   # unit tests
go test -tags integration ./internal/sshx/      # real sshd integration tests (needs docker)
```

## License

[MIT](LICENSE)
