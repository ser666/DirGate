package config

import (
	"os"
	"strings"
)

// LoadDotEnv 从 .env 读取 KEY=VALUE 注入环境变量（路径可用 SAL_ENV_FILE 覆盖）。
// 已存在的环境变量不覆盖（真实环境变量优先）；文件不存在属正常情况，静默返回。
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

// parseDotEnv 宽松解析：忽略空行/注释行，支持可选 export 前缀与引号包裹；
// 不剥离行内 #（密码可能含 #），非法行跳过。
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
