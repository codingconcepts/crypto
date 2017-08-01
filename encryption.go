package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

// Encrypt uses AES in GCM mode to encrypt a given plaintext.
func Encrypt(pt []byte, key [32]byte) (ct []byte, err error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return
	}

	return gcm.Seal(nonce, nonce, pt, nil), nil
}

// Decrypt uses AES in GCM mode to decrypt a given ciphertext.
func Decrypt(ct []byte, key [32]byte) (pt []byte, err error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return
	}

	return gcm.Open(nil, ct[:gcm.NonceSize()], ct[gcm.NonceSize():], nil)
}
