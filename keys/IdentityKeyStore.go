package keys

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"go.mau.fi/libsignal/ecc"
	"go.mau.fi/libsignal/keys/identity"
	"go.mau.fi/libsignal/serialize"
	"go.mau.fi/libsignal/util/keyhelper"
	"google.golang.org/protobuf/proto"
)

type IdentityKeyStore struct {
	identityKeyPair     *identity.KeyPair
	localRegistrationID uint32
}

type identityKeySerializer struct {
	private             string
	public              string
	localRegistrationID uint32
}

func GenerateIdentityKeyStore() IdentityKeyStore {
	identityKeyPair, err := keyhelper.GenerateIdentityKeyPair()
	if err != nil {
		panic("Unable to generate identity key pair!")
	}

	// Generate a registration id
	registrationID := keyhelper.GenerateRegistrationID()
	return IdentityKeyStore{
		identityKeyPair:     identityKeyPair,
		localRegistrationID: registrationID,
	}
}

func DeserializeIdentityKey(serialized []byte) (*IdentityKeyStore, error) {
	var serializer serialize.IdentityKeyPairStructure

	err := proto.Unmarshal(serialized, &serializer)
	if err != nil {
		return nil, err
	}

	var publicKey [32]byte
	copy(publicKey[:], serializer.PublicKey)
	key := identity.NewKeyFromBytes(publicKey, 0)

	var privateKey [32]byte
	copy(privateKey[:], serializer.PrivateKey)
	pair := identity.NewKeyPair(&key, ecc.NewDjbECPrivateKey(privateKey))

	registrationId := binary.BigEndian.Uint32(serialized[:4])

	return &IdentityKeyStore{
		identityKeyPair:     pair,
		localRegistrationID: registrationId,
	}, nil
}

func (store *IdentityKeyStore) Serialize() []byte {
	pair := store.identityKeyPair
	pub := pair.PublicKey().Serialize()
	pri := pair.PrivateKey().Serialize()

	serializer := identityKeySerializer{
		private:             hex.EncodeToString(pri[:]),
		public:              hex.EncodeToString(pub),
		localRegistrationID: store.localRegistrationID,
	}

	buffer, _ := json.Marshal(serializer)
	return buffer
}

func (store *IdentityKeyStore) GetIdentityKeyPair() *identity.KeyPair {
	return store.identityKeyPair
}

func (store *IdentityKeyStore) GetLocalRegistrationId() uint32 {
	return store.localRegistrationID
}
