package web

import (
	"embed"
	"html/template"
)

//go:embed templates static
var FS embed.FS

func ParseTemplates() (*template.Template, error) {
	return template.New("").ParseFS(FS, "templates/*.html")
}
