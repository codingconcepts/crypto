package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
)

// NewSigningKey generates an ECDSA P256 private key.
func NewSigningKey() (pri *ecdsa.PrivateKey, err error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// Sign performs an ECDSA signing and returns the signature.
func Sign(data []byte, pri *ecdsa.PrivateKey) (sig []byte, err error) {
	digest := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, pri, digest[:])
	if err != nil {
		return
	}

	curveByteLen := pri.Curve.Params().P.BitLen() / 8
	rBytes, sBytes := r.Bytes(), s.Bytes()

	sig = make([]byte, curveByteLen*2)
	copy(sig[curveByteLen-len(rBytes):], rBytes)
	copy(sig[curveByteLen*2-len(sBytes):], sBytes)

	return
}

// Verify performs an ECDSA verification of a given signature.
func Verify(data []byte, sig []byte, pub *ecdsa.PublicKey) bool {
	digest := sha256.Sum256(data)

	curveByteLen := pub.Curve.Params().P.BitLen() / 8
	r, s := new(big.Int), new(big.Int)
	r.SetBytes(sig[:curveByteLen])
	s.SetBytes(sig[curveByteLen:])

	return ecdsa.Verify(pub, digest[:], r, s)
}
