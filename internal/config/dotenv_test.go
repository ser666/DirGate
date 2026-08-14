package config

import (
	"os"
	"testing"
)

func TestParseDotEnv(t *testing.T) {
	const prefix = "SAL_DOTENV_TEST_"
	content := `
# 注释
SAL_DOTENV_TEST_A=hello
SAL_DOTENV_TEST_B="with spaces"
SAL_DOTENV_TEST_C='single'
export SAL_DOTENV_TEST_D=1
SAL_DOTENV_TEST_E=
`
	t.Cleanup(func() {
		for _, k := range []string{"A", "B", "C", "D", "E"} {
			_ = os.Unsetenv(prefix + k)
		}
	})
	if err := parseDotEnv(content); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"A": "hello",
		"B": "with spaces",
		"C": "single",
		"D": "1",
		"E": "",
	}
	for k, want := range cases {
		if got := os.Getenv(prefix + k); got != want {
			t.Fatalf("%s = %q, want %q", k, got, want)
		}
	}
}

func TestParseDotEnvDoesNotOverrideExisting(t *testing.T) {
	const key = "SAL_DOTENV_TEST_OVERRIDE"
	_ = os.Setenv(key, "from-env")
	t.Cleanup(func() { _ = os.Unsetenv(key) })
	if err := parseDotEnv(key + "=from-dotenv\n"); err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv(key); got != "from-env" {
		t.Fatalf("existing env must win, got %q", got)
	}
}

func TestParseDotEnvSkipsCommentsAndMalformed(t *testing.T) {
	content := "# only comment\n   \nNOEQUALS\n=novalue\nSAL_DOTENV_TEST_OK=1\n"
	t.Cleanup(func() { _ = os.Unsetenv("SAL_DOTENV_TEST_OK") })
	if err := parseDotEnv(content); err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv("SAL_DOTENV_TEST_OK"); got != "1" {
		t.Fatalf("got %q want 1", got)
	}
}
