# ServerAgentLink

**A single static binary. Zero external dependencies. Copy and run.**
Securely expose directories across multiple servers to your local agents — OS account provisioning + per-directory ACL grants + an MCP credential directory.

[中文](README_ZH.md) · [Guide (Chinese)](docs/使用说明.md)

## Why

Local assistant agents often work across many servers at once (read/write repos, inspect logs, edit configs) — but handing them a root password is unsafe and unauditable. ServerAgentLink is the **permission foundation** for that workflow:

- Admins register servers in a Web UI, provision **least-privilege OS accounts** for agents, and grant per-directory `rw`/`ro` ACLs;
- Agents fetch the full "server + account + directory list" through a single MCP tool, then work **only inside** granted directories — anything beyond the boundary is rejected at the OS level;
- Grants can carry an **expiry**: exposure vanishes from MCP automatically and the remote account gets locked.

The core idea: **authorization as the boundary**. Real access control is enforced by POSIX ACLs on the servers; the platform only handles provisioning and revocation.

## Quick start

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

## Features

- **Real provisioning**: `useradd` / `chpasswd` / `setfacl` / `userdel` executed for real; non-root admin accounts escalate via `sudo -n` automatically
- **Per-directory ACLs**: `rw`/`ro` grants include default ACLs (inherited by new files); ACLs revoked directory-by-directory before account deletion — no orphans
- **Expiry & reclamation**: `expires_at` → MCP exposure stops immediately → remote account locked (data preserved; renew + re-provision to restore)
- **MCP directory**: `list_exposed_accounts` returns only exposed, non-expired accounts on enabled servers
- **Secure defaults**: AES-256-GCM credentials at rest, argon2id admin hash, HMAC sessions + CSRF + login rate limiting, SSH TOFU fingerprints, operation audit log
- **Trivial deployment**: single static binary (pure Go, no cgo), SQLite with versioned auto-migrations, embedded Web UI, systemd unit and backup script included

## Documentation

- [Guide (Chinese)](docs/使用说明.md) — environment variables, API reference, MCP onboarding, security model, backup/restore, troubleshooting
- [deploy/](deploy/) — systemd unit template and backup script
- [.env.example](.env.example) — annotated configuration reference

## Scope

**Not doing**: task brokering (no agent orchestration), Anthropic API key management, multi-admin/RBAC, Kubernetes platformization.
**Planned**: multi-cloud instance ingestion, password rotation, server groups, alert notifications.

## Testing

```bash
go test ./...                                   # unit tests
go test -tags integration ./internal/sshx/      # real sshd integration tests (needs docker)
```

## License

[MIT](LICENSE)
