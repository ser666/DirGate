#!/usr/bin/env bash
# ServerAgentLink 一键启动脚本：生成 .env（若缺省）→ 构建 → 运行。
# 用法：./run.sh
set -euo pipefail
cd "$(dirname "$0")"

# 0) 前置检查：需要 Go 工具链
if ! command -v go >/dev/null 2>&1; then
  echo "错误：未找到 Go 工具链。请先安装 Go 1.26+（https://go.dev/dl/），再运行本脚本。" >&2
  exit 1
fi

# 1) 生成 .env（若不存在），并为 MCP token 填入随机强值，避免默认弱 token 上线
if [ ! -f .env ]; then
  cp .env.example .env
  if command -v openssl >/dev/null 2>&1; then
    token="$(openssl rand -hex 24)"
  elif [ -r /proc/sys/kernel/random/uuid ]; then
    token="$(cat /proc/sys/kernel/random/uuid)"
  else
    token="please-set-SAL_MCP_TOKEN"
  fi
  sed -i.bak "s|^SAL_MCP_TOKEN=.*|SAL_MCP_TOKEN=${token}|" .env
  rm -f .env.bak
  echo "已生成 .env（SAL_MCP_TOKEN 已随机生成）。按需编辑 .env 后再次运行，或直接继续。"
fi

# 2) 构建单二进制
echo "构建 server-agent-link ..."
go build -o server-agent-link ./cmd/server-agent-link

# 3) 启动（程序自身会读取 .env；真实环境变量优先于 .env）
echo "启动 ServerAgentLink ..."
exec ./server-agent-link
