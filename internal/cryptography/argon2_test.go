package cryptography

import (
	"strings"
	"testing"
)

func TestNewArgon2Default(t *testing.T) {
	password := "mySecretPassword"
	params := NewArgon2Default()
	hash := params.HashString(password)

	values := strings.Split(hash, "$")
	if len(values) != 2 {
		t.Errorf("Hash should be split in two parts")
	}

	if !params.VerifyString(password, values[0], values[1]) {
		t.Errorf("Password should be verified")
	}

	hashBytes := params.HashBytes([]byte(password))

	if !params.Verify([]byte(password), hashBytes, []byte(values[1])) {
		t.Errorf("Password should be verified")
	}
}
