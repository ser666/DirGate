package web

import (
	"bytes"
	"testing"
)

func TestParseTemplates(t *testing.T) {
	tmpl, err := ParseTemplates()
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]any{
		"login":         map[string]any{"Authed": false},
		"servers":       map[string]any{"Authed": true, "Servers": []map[string]any{}, "Exposed": []map[string]any{}},
		"server_detail": map[string]any{"Authed": true, "Server": map[string]any{"Name": "n", "Host": "h", "SSHPort": 22}, "Accounts": []map[string]any{}},
	}
	for name, data := range tests {
		var buf bytes.Buffer
		if err := tmpl.ExecuteTemplate(&buf, name, data); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
}
