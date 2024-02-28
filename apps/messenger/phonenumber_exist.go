package messenger

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/cristalhq/base64"
	"github.com/dajiangai/openwhatsapp/keys"
	"github.com/dajiangai/openwhatsapp/utils"
	"github.com/google/uuid"
	"go.mau.fi/libsignal/ecc"
)

type PhoneNumberExist struct {
	Cc        string `json:"cc"`
	In        string `json:"in"`
	Rc        string `json:"rc"`
	Lg        string `json:"lg"`
	Lc        string `json:"lc"`
	AuthKey   string `json:"authkey"`
	Eregid    string `json:"e_regid"`
	Ekeytype  string `json:"e_keytype"`
	Eident    string `json:"e_ident"`
	EskeyId   string `json:"e_skey_id"`
	EskeyVal  string `json:"e_skey_val"`
	EskeySig  string `json:"e_skey_sig"`
	Fdid      string `json:"fdid"`
	Expid     string `json:"expid"`
	OfflineAb string `json:"offline_ab"`
	Id        string `json:"id"`
}

type PhoneNumberExistResp struct {
	Login       string `json:"login"` //手机号
	Param       string `json:"param"`
	Status      string `json:"status"`       //状态
	Reason      string `json:"reason"`       //描述
	SmsLength   int    `json:"sms_length"`   //短信验证码长度 不关注这个字段
	VoiceLength int    `json:"voice_length"` //语音验证码长度 不关注这个字段
	SmsWait     int    `json:"sms_wait"`     //不关注这个字段
	VoiceWait   int    `json:"voice_wait"`   //不关注这个字段
}

type metricsModel struct {
	ExpidCd int32 `json:"expid_cd"`
	ExpidMd int32 `json:"expid_md"`
	RcC     bool  `json:"rc_c"`
}

type OfflineAbModel struct {
	Exposure []string      `json:"exposure"`
	Metrics  *metricsModel `json:"metrics"`
}

// Error .
func (p *PhoneNumberExistResp) Error() error {
	if p.Status == "fail" {
		if p.Reason == "incorrect" {
			return nil
		} else {
			return errors.New(p.Reason)
		}
	}
	return nil
}

func (app *Messenger) MakePhoneNumberExist() string {
	identityKeyPair := app.IdentityKeyStore.GetIdentityKeyPair()
	registrationId := app.IdentityKeyStore.GetLocalRegistrationId()
	signedPreKey := app.SignedPreKey

	identityPubKey := identityKeyPair.PublicKey().PublicKey().PublicKey()
	signedPreKeyPub := signedPreKey.KeyPair().PublicKey().PublicKey()
	signedPreKeySig := signedPreKey.Signature()

	uuid4, _ := uuid.Parse(app.Uuid)

	ab := OfflineAbModel{
		Exposure: make([]string, 0),
		Metrics: &metricsModel{
			ExpidCd: int32(app.FBUuidCreateTime),
			ExpidMd: int32(app.FBUuidCreateTime),
			RcC:     true,
		},
	}
	abJson, _ := json.Marshal(ab)

	model := PhoneNumberExist{
		Cc:        fmt.Sprintf("%v", app.CountryCode),
		In:        fmt.Sprintf("%v", app.NationalNumber),
		Rc:        "0",
		Lg:        app.Language,
		Lc:        app.Country,
		AuthKey:   base64.RawURLEncoding.EncodeToString(app.ClientStaticPubKey),
		Eregid:    base64.RawURLEncoding.EncodeToString(utils.UInt32ToBigEndianBytes(registrationId, 4)),
		Ekeytype:  base64.RawURLEncoding.EncodeToString(utils.UInt32ToBigEndianBytes(ecc.DjbType, 1)),
		Eident:    base64.RawURLEncoding.EncodeToString(identityPubKey[:]),
		EskeyId:   base64.RawURLEncoding.EncodeToString(utils.UInt32ToBigEndianBytes(signedPreKey.ID(), 3)),
		EskeyVal:  base64.RawURLEncoding.EncodeToString(signedPreKeyPub[:]),
		EskeySig:  base64.RawURLEncoding.EncodeToString(signedPreKeySig[:]),
		Fdid:      app.FBUuid,
		Expid:     base64.RawURLEncoding.EncodeToString(uuid4[:]),
		OfflineAb: keys.URLEncode(string(abJson)),
		Id:        keys.URLEncode(string(app.RecoveryToken)),
	}
	modelJson, _ := json.Marshal(model)
	modelParam := keys.GenURLParams(modelJson)
	modelResult := keys.AesGcmEncrypt(app.AesKey.AesKey, []byte(modelParam))

	var buffer bytes.Buffer
	buffer.Write(app.AesPubKey)
	buffer.Write(modelResult)

	result := base64.RawURLEncoding.EncodeToString(buffer.Bytes())
	return "/v2/exist?ENC=" + result
}
