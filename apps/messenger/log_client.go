package messenger

import (
	"bytes"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"github.com/cristalhq/base64"
	"github.com/google/uuid"
	"go.mau.fi/libsignal/ecc"
	"openws/keys"
	"openws/utils"
)

type ClientLog struct {
	Cc             string `json:"cc"`
	In             string `json:"in"`
	Rc             string `json:"rc"` // 0
	Lg             string `json:"lg"`
	Lc             string `json:"lc"`
	AuthKey        string `json:"authkey"`
	Eregid         string `json:"e_regid"`
	Ekeytype       string `json:"e_keytype"`
	Eident         string `json:"e_ident"`
	EskeyId        string `json:"e_skey_id"`
	EskeyVal       string `json:"e_skey_val"`
	EskeySig       string `json:"e_skey_sig"`
	Fdid           string `json:"fdid"`
	Expid          string `json:"expid"`
	CurrentScreen  string `json:"current_screen"`  // verify_sms
	PreviousScreen string `json:"previous_screen"` // enter_number
	ActionTaken    string `json:"action_taken"`    // continue
	Id             string `json:"id"`
}

// ClientLogResp .
type ClientLogResp struct {
	Login  string `json:"login"`  // 手机号
	Status string `json:"status"` // 状态
}

// Error .
func (p *ClientLogResp) Error() error {
	if p.Status == "ok" {
		return nil
	}

	return fmt.Errorf("log failed")
}

func (app *Messenger) MakeClientLog(actionTaken, previousScreen, currentScreen string) string {
	identityKeyPair := app.IdentityKeyStore.GetIdentityKeyPair()
	registrationId := app.IdentityKeyStore.GetLocalRegistrationId()
	signedPreKey := app.SignedPreKey

	identityPubKey := identityKeyPair.PublicKey().PublicKey().PublicKey()
	signedPreKeyPub := signedPreKey.KeyPair().PublicKey().PublicKey()
	signedPreKeySig := signedPreKey.Signature()

	uuid4, _ := uuid.Parse(app.Uuid)

	h := md5.New()
	h.Write([]byte(AESPassword + BuildHash + fmt.Sprintf("%v", app.NationalNumber)))

	model := ClientLog{
		Cc:             fmt.Sprintf("%v", app.CountryCode),
		In:             fmt.Sprintf("%v", app.NationalNumber),
		Rc:             "0",
		Lg:             app.Apple.Language,
		Lc:             app.Country,
		AuthKey:        base64.RawURLEncoding.EncodeToString(app.ClientStaticPubKey),
		Eregid:         base64.RawURLEncoding.EncodeToString(utils.UInt32ToBigEndianBytes(registrationId, 4)),
		Ekeytype:       base64.RawURLEncoding.EncodeToString(utils.UInt32ToBigEndianBytes(ecc.DjbType, 1)),
		Eident:         base64.RawURLEncoding.EncodeToString(identityPubKey[:]),
		EskeyId:        base64.RawURLEncoding.EncodeToString(utils.UInt32ToBigEndianBytes(signedPreKey.ID(), 3)),
		EskeyVal:       base64.RawURLEncoding.EncodeToString(signedPreKeyPub[:]),
		EskeySig:       base64.RawURLEncoding.EncodeToString(signedPreKeySig[:]),
		Fdid:           app.FBUuid,
		Expid:          base64.RawURLEncoding.EncodeToString(uuid4[:]),
		Id:             keys.URLEncode(string(app.RecoveryToken)),
		ActionTaken:    actionTaken,
		PreviousScreen: previousScreen,
		CurrentScreen:  currentScreen,
	}
	modelJson, _ := json.Marshal(model)
	modelParam := keys.GenURLParams(modelJson)
	modelResult := keys.AesGcmEncrypt(app.AesKey.AesKey, []byte(modelParam))

	var buffer bytes.Buffer
	buffer.Write(app.AesPubKey)
	buffer.Write(modelResult)

	result := base64.RawURLEncoding.EncodeToString(buffer.Bytes())
	return "/v2/client_log?ENC=" + result
}
