package config

import (
	"os"
	"strings"
)

// LoadDotEnv 从 .env 文件读取 KEY=VALUE 并写入环境变量，使项目可「下载即配置」。
// 路径可用环境变量 SAL_ENV_FILE 覆盖（默认工作目录下的 .env）。
// 已存在的环境变量不会被覆盖（真实环境变量优先于 .env），保证运维可显式覆盖。
// 文件不存在时静默返回 nil——「未使用 .env」属正常情况。
func LoadDotEnv() error {
	path := os.Getenv("SAL_ENV_FILE")
	if path == "" {
		path = ".env"
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return parseDotEnv(string(b))
}

// parseDotEnv 解析 .env 内容：忽略空行与 # 注释，支持可选 `export ` 前缀与
// 单/双引号包裹的值；不剥离行内 #（密码等值可能含 #）。格式非法行宽松跳过。
func parseDotEnv(content string) error {
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "export ") {
			line = strings.TrimSpace(line[len("export "):])
		}
		eq := strings.Index(line, "=")
		if eq < 0 {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])
		if key == "" {
			continue
		}
		val = unquote(val)
		if _, exists := os.LookupEnv(key); exists {
			continue // 环境变量优先
		}
		_ = os.Setenv(key, val)
	}
	return nil
}

func unquote(s string) string {
	if len(s) >= 2 {
		q := s[0]
		if (q == '"' || q == '\'') && s[len(s)-1] == q {
			return s[1 : len(s)-1]
		}
	}
	return s
}
