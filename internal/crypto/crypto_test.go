package crypto

import (
	"bytes"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	ct, err := Encrypt(key, []byte("secret-password"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := Decrypt(key, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, []byte("secret-password")) {
		t.Fatalf("got %q", pt)
	}
}

func TestDecryptWrongKeyFails(t *testing.T) {
	k1 := make([]byte, 32)
	k2 := make([]byte, 32)
	k2[0] = 1
	ct, _ := Encrypt(k1, []byte("x"))
	if _, err := Decrypt(k2, ct); err == nil {
		t.Fatal("expected error")
	}
}

func TestPasswordHashVerify(t *testing.T) {
	h, err := HashPassword("admin-pass")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(h, "admin-pass") {
		t.Fatal("should verify")
	}
	if VerifyPassword(h, "wrong") {
		t.Fatal("should not verify")
	}
}

func TestRandomIDUnique(t *testing.T) {
	a, _ := RandomID()
	b, _ := RandomID()
	if a == b || len(a) != 32 {
		t.Fatalf("a=%q b=%q", a, b)
	}
}

func TestRandomToken(t *testing.T) {
	tok, err := RandomToken()
	if err != nil {
		t.Fatal(err)
	}
	if len(tok) != 43 {
		t.Fatalf("token len=%d (%q)", len(tok), tok)
	}
}
