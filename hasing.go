package crypto

import (
	"crypto/hmac"
	"crypto/sha512"

	"golang.org/x/crypto/bcrypt"
)

// HashData performs an HMAC SHA-512/256 hash of a given input.
// Note that this should only be used to hash data, not passwords.
func HashData(tag string, data []byte) (digest []byte) {
	h := hmac.New(sha512.New512_256, []byte(tag))
	h.Write(data)
	return h.Sum(nil)
}

// HashPassword performs a bcrypt hash of a given password using
// a constant cost value.
func HashPassword(password []byte) (digest []byte, err error) {
	return bcrypt.GenerateFromPassword(password, 14)
}

// CheckPassword compares a given password against its hased
// equivalent and returns an error if they are not equal.
func CheckPassword(digest []byte, password []byte) (err error) {
	return bcrypt.CompareHashAndPassword(digest, password)
}
