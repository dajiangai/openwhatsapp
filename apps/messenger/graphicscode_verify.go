package messenger

import (
	"bytes"
	"crypto/md5"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/cristalhq/base64"
	"github.com/google/uuid"
	"go.mau.fi/libsignal/ecc"
	"math/rand"
	"openws/keys"
	"openws/utils"
)

type GraphicsCodeVerify struct {
	Cc                  string `json:"cc"`
	In                  string `json:"in"`
	Rc                  string `json:"rc"`
	Lg                  string `json:"lg"`
	Lc                  string `json:"lc"`
	AuthKey             string `json:"authkey"`
	Eregid              string `json:"e_regid"`
	Ekeytype            string `json:"e_keytype"`
	Eident              string `json:"e_ident"`
	EskeyId             string `json:"e_skey_id"`
	EskeyVal            string `json:"e_skey_val"`
	EskeySig            string `json:"e_skey_sig"`
	Fdid                string `json:"fdid"`
	Expid               string `json:"expid"`
	FraudCheckpointCode string `json:"fraud_checkpoint_code"`
	AudioButtonTapCount int    `json:"audio_button_tap_count"`
	Id                  string `json:"id"`
}

type GraphicsCodeVerifyResp struct {
	EmailOtpEligible int    `json:"email_otp_eligible"`
	FlashType        int    `json:"flash_type"`
	Login            string `json:"login"`
	SmsLength        int    `json:"sms_length"`
	SmsWait          int    `json:"sms_wait"`
	Status           string `json:"status"`
	VoiceLength      int    `json:"voice_length"`
	VoiceWait        int    `json:"voice_wait"`
	WaOldEligible    int    `json:"wa_old_eligible"`
}

// HasError .
func (p *GraphicsCodeVerifyResp) Error() error {
	if p.Status == "verified" {
		return nil
	} else {
		return errors.New("unknown")
	}
}

func (app *Messenger) MakeGraphicsCodeVerify(checkpoint string) string {
	identityKeyPair := app.IdentityKeyStore.GetIdentityKeyPair()
	registrationId := app.IdentityKeyStore.GetLocalRegistrationId()
	signedPreKey := app.SignedPreKey

	identityPubKey := identityKeyPair.PublicKey().PublicKey().PublicKey()
	signedPreKeyPub := signedPreKey.KeyPair().PublicKey().PublicKey()
	signedPreKeySig := signedPreKey.Signature()

	uuid4, _ := uuid.Parse(app.Uuid)

	h := md5.New()
	h.Write([]byte(AESPassword + BuildHash + fmt.Sprintf("%v", app.NationalNumber)))

	model := GraphicsCodeVerify{
		Cc:                  fmt.Sprintf("%v", app.CountryCode),
		In:                  fmt.Sprintf("%v", app.NationalNumber),
		Rc:                  "0",
		Lg:                  app.Language,
		Lc:                  app.Country,
		AuthKey:             base64.RawURLEncoding.EncodeToString(app.ClientStaticPubKey),
		Eregid:              base64.RawURLEncoding.EncodeToString(utils.UInt32ToBigEndianBytes(registrationId, 4)),
		Ekeytype:            base64.RawURLEncoding.EncodeToString(utils.UInt32ToBigEndianBytes(ecc.DjbType, 1)),
		Eident:              base64.RawURLEncoding.EncodeToString(identityPubKey[:]),
		EskeyId:             base64.RawURLEncoding.EncodeToString(utils.UInt32ToBigEndianBytes(signedPreKey.ID(), 3)),
		EskeyVal:            base64.RawURLEncoding.EncodeToString(signedPreKeyPub[:]),
		EskeySig:            base64.RawURLEncoding.EncodeToString(signedPreKeySig[:]),
		Fdid:                app.FBUuid,
		Expid:               base64.RawURLEncoding.EncodeToString(uuid4[:]),
		FraudCheckpointCode: checkpoint,
		AudioButtonTapCount: rand.Intn(5),
		Id:                  keys.URLEncode(string(app.RecoveryToken)),
	}
	modelJson, _ := json.Marshal(model)
	modelParam := keys.GenURLParams(modelJson)
	modelResult := keys.AesGcmEncrypt(app.AesKey.AesKey, []byte(modelParam))

	var buffer bytes.Buffer
	buffer.Write(app.AesPubKey)
	buffer.Write(modelResult)

	result := base64.RawURLEncoding.EncodeToString(buffer.Bytes())
	return "/v2/captcha_verify?ENC=" + result
}
