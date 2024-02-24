package keys

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"go.mau.fi/libsignal/ecc"
	"go.mau.fi/libsignal/keys/identity"
	"golang.org/x/crypto/curve25519"
	mathRand "math/rand"
)

var AESCurve25519PublicKey = []byte{
	0x8e, 0x8c, 0x0f, 0x74, 0xc3, 0xeb, 0xc5, 0xd7,
	0xa6, 0x86, 0x5c, 0x6c, 0x3c, 0x84, 0x38, 0x56,
	0xb0, 0x61, 0x21, 0xcc, 0xe8, 0xea, 0x77, 0x4d,
	0x22, 0xfb, 0x6f, 0x12, 0x25, 0x12, 0x30, 0x2d,
}

func AesGcmEncrypt(aesKey []byte, content []byte) []byte {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil
	}

	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, 12)

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil
	}

	return aesgcm.Seal(nil, nonce, content, nil)
}

func GenCurve25519KeyPair() ([]byte, []byte) {
	var priKey, pubKey [32]byte

	//用随机数填满私钥
	_, err := rand.Reader.Read(priKey[:])
	if err != nil {
		return nil, nil
	}

	curve25519.ScalarBaseMult(&pubKey, &priKey)

	return pubKey[:], priKey[:]
}

func CalCurve25519Signature(priKey []byte, message []byte) []byte {
	for {
		// when provided a low-order point, ScalarMult will set dst to all
		// zeroes, irrespective of the scalar.
		signature, err := curve25519.X25519(priKey, message)
		if err == nil {
			return signature
		}
	}
}

func GenerateSignedPreKeyID() uint32 {
	// 				100000 < ID < 0xFFFFFF(16777215)
	return uint32(100000 + mathRand.Int31n(0xFFFFFF-100000))
}

func GeneratePublicKeyFromPrivateKey(priv [32]byte) []byte {
	var pub [32]byte
	curve25519.ScalarBaseMult(&pub, &priv)

	return pub[:]
}

func GenerateIdentityKeyPairFromPrivateKey(priv [32]byte) *identity.KeyPair {
	var pub [32]byte
	curve25519.ScalarBaseMult(&pub, &priv)

	publicKey := identity.NewKey(ecc.NewDjbECPublicKey(pub))
	privateKey := ecc.NewDjbECPrivateKey(priv)
	return identity.NewKeyPair(publicKey, privateKey)
}

func RandomKeyPair() ([32]byte, [32]byte) {
	var pri [32]byte
	_, _ = rand.Read(pri[:])

	pri[0] &= 248
	pri[31] &= 127
	pri[31] |= 64

	var pub [32]byte
	curve25519.ScalarBaseMult(&pub, &pri)
	return pub, pri
}
