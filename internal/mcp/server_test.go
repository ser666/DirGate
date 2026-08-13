package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"serveragentlink/internal/store"
)

func newHandler(t *testing.T) (http.Handler, *store.Store) {
	t.Helper()
	key := make([]byte, 32)
	st, err := store.Open(t.TempDir(), key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	h, err := NewHandler(st, key, "secrettoken")
	if err != nil {
		t.Fatal(err)
	}
	return h, st
}

func TestBearerAuthRequired(t *testing.T) {
	h, _ := newHandler(t)
	req := httptest.NewRequest("POST", "/mcp", bytes.NewReader([]byte(`{}`)))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code=%d", rec.Code)
	}
}

func TestToolsListed(t *testing.T) {
	h, _ := newHandler(t)
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`
	req := httptest.NewRequest("POST", "/mcp", bytes.NewReader([]byte(body)))
	req.Header.Set("Authorization", "Bearer secrettoken")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body)
	}
	var resp struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, rec.Body)
	}
	if len(resp.Result.Tools) != 1 || resp.Result.Tools[0].Name != "list_exposed_accounts" {
		t.Fatalf("tools=%+v", resp.Result.Tools)
	}
}

func TestListExposedAccountsTool(t *testing.T) {
	h, st := newHandler(t)

	sv, err := st.CreateServer(context.Background(), "dev1", "10.0.0.1", 22, "root", "rootpw")
	if err != nil {
		t.Fatal(err)
	}
	a1, err := st.CreateAccount(context.Background(), sv.ID, "alice", "alicepw", true, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateAccount(context.Background(), sv.ID, "bob", "bobpw", false, false); err != nil {
		t.Fatal(err)
	}
	perms := []store.DirectoryPermission{
		{Path: "/data/a", Mode: store.ModeReadWrite},
		{Path: "/data/b", Mode: store.ModeReadOnly},
	}
	if err := st.SetPermissions(context.Background(), a1.ID, perms); err != nil {
		t.Fatal(err)
	}

	body := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_exposed_accounts","arguments":{}}}`
	req := httptest.NewRequest("POST", "/mcp", bytes.NewReader([]byte(body)))
	req.Header.Set("Authorization", "Bearer secrettoken")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body)
	}

	// 断言响应中包含解密后的凭据，且未包含未暴露账户。
	raw := rec.Body.String()
	if !bytes.Contains(rec.Body.Bytes(), []byte(`"username":"alice"`)) {
		t.Fatalf("missing alice: %s", raw)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte(`"password":"alicepw"`)) {
		t.Fatalf("missing decrypted password: %s", raw)
	}
	if bytes.Contains(rec.Body.Bytes(), []byte(`"bob"`)) {
		t.Fatalf("must not expose non-exposed account: %s", raw)
	}
}
