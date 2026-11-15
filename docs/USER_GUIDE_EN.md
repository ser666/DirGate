# ServerAgentLink User Guide

> Complete operations manual for administrators. For a quick overview see the [README](../README.md).

> **Note**: This guide is currently available in Chinese only: [使用说明（中文）](使用说明.md). The English translation covers the same content: concepts & architecture, installation (one-command / manual / cross-compile / systemd), environment variables, first run, the full Web UI workflow, the root/sudo/plain access-mode tiers, account expiry & reclamation, the complete REST API reference, MCP onboarding with the `list_exposed_accounts` tool, the four-layer security model, backup/restore, a troubleshooting table, and the explicit non-goals.

Key operations at a glance:

```bash
./run.sh                                  # start (generates .env, builds, runs)
./deploy/backup.sh ./data ./backups       # back up db + master.key together
journalctl -t server-agent-link -g audit  # audit trail (under systemd)
```

Add a server → run "Test Connection" (probes root/sudo/plain tier) → create or attach accounts → grant per-directory `rw`/`ro` ACLs → flip "Expose" → optionally set an expiry. Agents fetch everything via one MCP tool.
