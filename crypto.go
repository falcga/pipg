package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

func deriveKey(psk string) []byte {
	h := sha256.Sum256([]byte(psk))
	return h[:]
}

func encryptChunk(key []byte, plaintext []byte, cipherName string) (nonce []byte, ciphertext []byte, err error) {
	switch cipherName {
	case CIPHER_CHACHA20:
		return encryptChacha20(key, plaintext)
	default:
		return encryptAESGCM(key, plaintext)
	}
}

func decryptChunk(key []byte, nonce []byte, ciphertext []byte, cipherName string) ([]byte, error) {
	switch cipherName {
	case CIPHER_CHACHA20:
		return decryptChacha20(key, nonce, ciphertext)
	default:
		return decryptAESGCM(key, nonce, ciphertext)
	}
}

func encryptAESGCM(key []byte, plaintext []byte) (nonce []byte, ciphertext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, NONCE_SIZE)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return nonce, ciphertext, nil
}

func decryptAESGCM(key []byte, nonce []byte, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func encryptChacha20(key []byte, plaintext []byte) (nonce []byte, ciphertext []byte, err error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	ciphertext = aead.Seal(nil, nonce, plaintext, nil)
	return nonce, ciphertext, nil
}

func decryptChacha20(key []byte, nonce []byte, ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, nil)
}
