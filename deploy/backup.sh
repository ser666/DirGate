#!/bin/sh
# 备份 ServerAgentLink 数据目录：SQLite + master.key + admin-password.txt。
# 两者必须成对备份——master.key 丢失即库内全部密文永久不可解。
# 用法：./deploy/backup.sh [数据目录] [输出目录]
# 恢复：tar xzf server-agent-link-<ts>.tgz -C <数据目录父目录>
set -eu

DATA_DIR="${1:-./data}"
OUT_DIR="${2:-./backups}"

if [ ! -f "$DATA_DIR/master.key" ]; then
  echo "error: $DATA_DIR/master.key not found (wrong SAL_DATA_DIR?)" >&2
  exit 1
fi
if [ ! -f "$DATA_DIR/server-agent-link.db" ]; then
  echo "error: $DATA_DIR/server-agent-link.db not found" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"
TS=$(date -u +%Y%m%dT%H%M%SZ)
OUT="$OUT_DIR/server-agent-link-$TS.tgz"

# 先用 sqlite3 在线快照保证一致性；无 sqlite3 时回退直接拷贝（建议停服后恢复）。
if command -v sqlite3 >/dev/null 2>&1; then
  TMP=$(mktemp -d)
  trap 'rm -rf "$TMP"' EXIT
  sqlite3 "$DATA_DIR/server-agent-link.db" ".backup '$TMP/server-agent-link.db'"
  cp "$DATA_DIR/master.key" "$TMP/"
  [ -f "$DATA_DIR/admin-password.txt" ] && cp "$DATA_DIR/admin-password.txt" "$TMP/"
  tar czf "$OUT" -C "$TMP" .
else
  tar czf "$OUT" -C "$DATA_DIR" server-agent-link.db master.key admin-password.txt 2>/dev/null \
    || tar czf "$OUT" -C "$DATA_DIR" server-agent-link.db master.key
fi
chmod 600 "$OUT"
echo "backup written: $OUT"
echo "keep db and master.key together; losing master.key = permanent data loss"
