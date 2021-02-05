package gotion

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// ArgonConfig struct
type ArgonConfig struct {
	keyLen  uint32
	memory  uint32
	threads uint8
	time    uint32
}

// Hash function using Argon2
func Hash(password string, config *ArgonConfig) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	result := argon2.IDKey([]byte(password), salt, config.time, config.memory, config.threads, config.keyLen)
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(result)
	format := "$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s"
	hash := fmt.Sprintf(format, argon2.Version, config.memory, config.time, config.threads, b64Salt, b64Hash)
	return hash, nil
}

// Verify function using Argon2
func Verify(password, hash string) (bool, error) {
	parts := strings.Split(hash, "$")
	config := &ArgonConfig{}
	_, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &config.memory, &config.time, &config.threads)
	if err != nil {
		return false, err
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, err
	}
	decodedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, err
	}
	config.keyLen = uint32(len(decodedHash))
	comparisonHash := argon2.IDKey([]byte(password), salt, config.time, config.memory, config.threads, config.keyLen)
	return (subtle.ConstantTimeCompare(decodedHash, comparisonHash) == 1), nil
}
