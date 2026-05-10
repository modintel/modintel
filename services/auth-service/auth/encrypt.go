package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
)

// EncryptString encrypts plaintext using AES-256-GCM with the given key.
// The key must be exactly 32 bytes (use the first 32 bytes of JWT_SECRET).
// Returns a hex-encoded ciphertext (nonce + ciphertext).
func EncryptString(plaintext, key string) (string, error) {
	keyBytes := normaliseKey(key)

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return hex.EncodeToString(ciphertext), nil
}

// DecryptString decrypts a hex-encoded ciphertext produced by EncryptString.
func DecryptString(ciphertextHex, key string) (string, error) {
	keyBytes := normaliseKey(key)

	data, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		return "", errors.New("invalid ciphertext encoding")
	}

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", errors.New("decryption failed")
	}

	return string(plaintext), nil
}

// normaliseKey pads or truncates the key to exactly 32 bytes for AES-256.
func normaliseKey(key string) []byte {
	b := make([]byte, 32)
	copy(b, []byte(key))
	return b
}
