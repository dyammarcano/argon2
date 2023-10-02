package cryptography

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/dyammarcano/base58"
	"golang.org/x/crypto/argon2"
)

const (
	Base64 EncodeType = "base64"
	Base58 EncodeType = "base58"
	Hex    EncodeType = "hex"
)

type (
	EncodeType string

	Params struct {
		memory      uint32
		iterations  uint32
		parallelism uint8
		saltLength  uint32
		keyLength   uint32
		encodeType  EncodeType
	}
)

func NewArgon2Default() *Params {
	return &Params{
		memory:      64 * 1024,
		iterations:  3,
		parallelism: 4,
		saltLength:  16,
		keyLength:   32,
		encodeType:  Hex,
	}
}

func NewArgon2(saltSize uint32, encode EncodeType) *Params {
	return &Params{
		memory:      64 * 1024,
		iterations:  3,
		parallelism: 4,
		saltLength:  saltSize,
		keyLength:   32,
		encodeType:  encode,
	}
}

// HashString returns a string with the hash and salt encoded and separated by a $.
func (p *Params) HashString(password string) string {
	salt := p.generateSalt()
	hash, _ := p.Hash([]byte(password), salt)
	return fmt.Sprintf("%s$%s", p.encodeToString(hash), p.encodeToString(salt))
}

func (p *Params) HashBytes(password []byte) []byte {
	result := p.HashString(string(password))
	return []byte(result)
}

func (p *Params) Verify(password, hash, salt []byte) bool {
	encodedHash, _ := p.decodeString(string(hash))
	encodedSalt, _ := p.decodeString(string(salt))

	return subtle.ConstantTimeCompare(encodedHash, p.hashPassword(password, encodedSalt)) == 1
}

func (p *Params) VerifyString(password, hash, salt string) bool {
	return p.Verify([]byte(password), []byte(hash), []byte(salt))
}

func (p *Params) generateSalt() []byte {
	salt := make([]byte, p.saltLength)
	if _, err := rand.Read(salt); err != nil {
		panic(err)
	}

	return salt
}

func (p *Params) hashPassword(password, salt []byte) []byte {
	return argon2.IDKey(password, salt, p.iterations, p.memory, p.parallelism, p.keyLength)
}

func (p *Params) encodeToString(b []byte) string {
	switch p.encodeType {
	case Base64:
		return base64.RawStdEncoding.EncodeToString(b)
	case Base58:
		return base58.StdEncoding.EncodeToString(b)
	case Hex:
		return hex.EncodeToString(b)
	default:
		return hex.EncodeToString(b)

	}
}

func (p *Params) decodeString(s string) ([]byte, error) {
	switch p.encodeType {
	case Base64:
		return base64.RawStdEncoding.DecodeString(s)
	case Base58:
		return base58.StdEncoding.DecodeString(s)
	case Hex:
		return hex.DecodeString(s)
	default:
		return hex.DecodeString(s)
	}
}

func (p *Params) Hash(password, salt []byte) ([]byte, []byte) {
	return p.hashPassword(password, salt), salt
}
