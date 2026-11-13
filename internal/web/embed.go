package web

import (
	"embed"
	"html/template"
	"strings"
	"time"

	"serveragentlink/internal/store"
)

//go:embed templates static
var FS embed.FS

// Funcs 是模板自定义函数；必须在 ParseFS 之前注入，语法期即需可见。
var Funcs = template.FuncMap{
	// permSpec 把权限清单渲染成「/path=mode,/path=mode」紧凑串。
	"permSpec": permSpec,
	// expired 判断 RFC3339 到期时刻是否已过（空串 = 永不到期）。
	"expired": func(expiresAt string) bool {
		if expiresAt == "" {
			return false
		}
		t, err := time.Parse(time.RFC3339, expiresAt)
		return err == nil && !t.After(time.Now())
	},
}

func permSpec(perms []store.DirectoryPermission) string {
	parts := make([]string, 0, len(perms))
	for _, p := range perms {
		parts = append(parts, p.Path+"="+p.Mode)
	}
	return strings.Join(parts, ",")
}

func ParseTemplates() (*template.Template, error) {
	return template.New("").Funcs(Funcs).ParseFS(FS, "templates/*.html")
}
