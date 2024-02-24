package messenger

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/cristalhq/base64"
	"github.com/google/uuid"
	"go.mau.fi/libsignal/ecc"
	"openws/keys"
	"openws/utils"
)

type GraphicsCodeRequest struct {
	Cc       string `json:"cc"`
	In       string `json:"in"`
	Rc       string `json:"rc"`
	Lg       string `json:"lg"`
	Lc       string `json:"lc"`
	AuthKey  string `json:"authkey"`
	Eregid   string `json:"e_regid"`
	Ekeytype string `json:"e_keytype"`
	Eident   string `json:"e_ident"`
	EskeyId  string `json:"e_skey_id"`
	EskeyVal string `json:"e_skey_val"`
	EskeySig string `json:"e_skey_sig"`
	Fdid     string `json:"fdid"`
	Expid    string `json:"expid"`
	Method   string `json:"method"`
	SimMcc   string `json:"sim_mcc"`
	SimMnc   string `json:"sim_mnc"`
	Token    string `json:"token"`
	Id       string `json:"id"`
}

type GraphicsCodeResp struct {
	AudioBlob string `json:"audio_blob"`
	ImageBlob string `json:"image_blob"`
	Login     string `json:"login"`
	Status    string `json:"status"`
}

// HasError .
func (p *GraphicsCodeResp) Error() error {
	if p.Status == "sent" {
		return nil
	} else {
		return errors.New("unknown")
	}
}

func (app *Messenger) MakeGraphicsCodeRequest() string {
	identityKeyPair := app.IdentityKeyStore.GetIdentityKeyPair()
	registrationId := app.IdentityKeyStore.GetLocalRegistrationId()
	signedPreKey := app.SignedPreKey

	identityPubKey := identityKeyPair.PublicKey().PublicKey().PublicKey()
	signedPreKeyPub := signedPreKey.KeyPair().PublicKey().PublicKey()
	signedPreKeySig := signedPreKey.Signature()

	uuid4, _ := uuid.Parse(app.Uuid)

	h := md5.New()
	h.Write([]byte(AESPassword + BuildHash + fmt.Sprintf("%v", app.NationalNumber)))

	model := GraphicsCodeRequest{
		Cc:       fmt.Sprintf("%v", app.CountryCode),
		In:       fmt.Sprintf("%v", app.NationalNumber),
		Rc:       "0",
		Lg:       app.Language,
		Lc:       app.Country,
		AuthKey:  base64.RawURLEncoding.EncodeToString(app.ClientStaticPubKey),
		Eregid:   base64.RawURLEncoding.EncodeToString(utils.UInt32ToBigEndianBytes(registrationId, 4)),
		Ekeytype: base64.RawURLEncoding.EncodeToString(utils.UInt32ToBigEndianBytes(ecc.DjbType, 1)),
		Eident:   base64.RawURLEncoding.EncodeToString(identityPubKey[:]),
		EskeyId:  base64.RawURLEncoding.EncodeToString(utils.UInt32ToBigEndianBytes(signedPreKey.ID(), 3)),
		EskeyVal: base64.RawURLEncoding.EncodeToString(signedPreKeyPub[:]),
		EskeySig: base64.RawURLEncoding.EncodeToString(signedPreKeySig[:]),
		Fdid:     app.FBUuid,
		Expid:    base64.RawURLEncoding.EncodeToString(uuid4[:]),
		Method:   "captcha",
		SimMcc:   app.MCC,
		SimMnc:   app.MNC,
		Token:    hex.EncodeToString(h.Sum(nil)),
		Id:       keys.URLEncode(string(app.RecoveryToken)),
	}
	modelJson, _ := json.Marshal(model)
	modelParam := keys.GenURLParams(modelJson)
	modelResult := keys.AesGcmEncrypt(app.AesKey.AesKey, []byte(modelParam))

	var buffer bytes.Buffer
	buffer.Write(app.AesPubKey)
	buffer.Write(modelResult)

	result := base64.RawURLEncoding.EncodeToString(buffer.Bytes())
	return "/v2/code?ENC=" + result
}
