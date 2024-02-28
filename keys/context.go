package keys

import (
	"encoding/hex"
	"github.com/dajiangai/openwhatsapp/utils"
	"github.com/google/uuid"
	"go.mau.fi/libsignal/ecc"
	"go.mau.fi/libsignal/serialize"
	"go.mau.fi/libsignal/state/record"
	"go.mau.fi/libsignal/util/keyhelper"
	"strings"
	"time"
)

type Context struct {
	JID                string
	NickName           string
	Uuid               string
	FBUuid             string
	PrivateStatsId     string
	ClientStaticPriKey []byte
	ClientStaticPubKey []byte
	ServerStaticKey    []byte
	EdgeRouting        []byte
	FBUuidCreateTime   int64

	IdentityKeyStore
	*record.SignedPreKey
	RegistrationToken
	AesKey
}

type RegistrationToken struct {
	RecoveryToken []byte
	BackupToken   []byte
	BackupKey     []byte
	BackupKey2    []byte
}

type AesKey struct {
	AesKey    []byte
	AesPubKey []byte
	AesPriKey []byte
}

func GenerateContext() (context Context) {
	context.NickName = "Lily"
	context.Uuid = strings.ToUpper(uuid.New().String())
	context.FBUuid = strings.ToUpper(uuid.New().String())
	context.PrivateStatsId = strings.ToUpper(uuid.New().String())
	context.FBUuidCreateTime = time.Now().Unix()

	djbECKeyPair, _ := ecc.GenerateKeyPair()
	clientStaticPriKey := djbECKeyPair.PrivateKey().Serialize()
	clientStaticPubKey := djbECKeyPair.PublicKey().PublicKey()
	context.ClientStaticPubKey = clientStaticPubKey[:]
	context.ClientStaticPriKey = clientStaticPriKey[:]

	// signal
	identityKeyStore := GenerateIdentityKeyStore()
	keyPair := identityKeyStore.GetIdentityKeyPair()

	identityPriKey := keyPair.PrivateKey().Serialize()
	idKeyPair := GenerateIdentityKeyPairFromPrivateKey(identityPriKey)
	signedPreKey, err := keyhelper.GenerateSignedPreKey(idKeyPair, GenerateSignedPreKeyID(), serialize.NewJSONSerializer().SignedPreKeyRecord)
	if err != nil {
		panic("GenerateSignedPreKeyStore error")
	}

	context.SignedPreKey = signedPreKey
	context.IdentityKeyStore = identityKeyStore

	// RegistrationToken
	context.RegistrationToken.RecoveryToken = utils.RandBytes(16)
	context.RegistrationToken.BackupToken = utils.RandBytes(20)
	context.RegistrationToken.BackupKey = make([]byte, 0)
	context.RegistrationToken.BackupKey2 = make([]byte, 0)

	// AesKey
	context.AesPubKey, context.AesPriKey = GenCurve25519KeyPair()
	context.AesKey.AesKey = CalCurve25519Signature(context.AesPriKey, AESCurve25519PublicKey)
	return
}

func (c *Context) DeserializeStaticKey(clientStaticPrivateKey string) error {
	buff, err := hex.DecodeString(clientStaticPrivateKey)
	if err != nil {
		return err
	}

	var pri [32]byte
	copy(pri[:], buff)

	c.ClientStaticPubKey = GeneratePublicKeyFromPrivateKey(pri)
	c.ClientStaticPriKey = pri[:]
	return nil
}
