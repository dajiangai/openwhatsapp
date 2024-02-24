package messenger

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/gogf/gf/net/ghttp"
	"github.com/ttacon/libphonenumber"
	"openws/fake"
	"openws/keys"
	"strings"
	"time"
)

type Messenger struct {
	*ghttp.Client
	keys.Context
	fake.Apple

	PhoneNumber    string
	Proxy          string
	CountryCode    int32
	Country        string
	NationalNumber uint64
}

func NewMessenger(phoneNumber, country, proxy string) *Messenger {
	country = strings.ToUpper(country)
	pn, err := libphonenumber.Parse(phoneNumber, country)
	if err != nil {
		return nil
	}

	apple := fake.NewApple()

	cli := ghttp.NewClient()
	cli.SetProxy(proxy)
	cli.SetContentType("text/json:charset=utf-8")
	cli.SetAgent(UserAgentString(apple))

	cli.SetTimeout(10 * time.Second)
	cli.SetTLSConfig(&tls.Config{InsecureSkipVerify: true})

	return &Messenger{
		Context:        keys.GenerateContext(),
		Apple:          apple,
		PhoneNumber:    phoneNumber,
		Proxy:          proxy,
		Country:        country,
		Client:         cli,
		CountryCode:    pn.GetCountryCode(),
		NationalNumber: pn.GetNationalNumber(),
	}
}

func (app *Messenger) Request(url string) ([]byte, error) {
	resp, err := app.Client.Get(url)
	if err != nil {
		return nil, err
	}

	defer func() {
		_ = resp.Close()
	}()

	buff := resp.ReadAll()
	return buff, nil
}

func (app *Messenger) Run() error {
	var (
		buff []byte
		err  error
	)

	buff, err = app.Request(Remote + app.MakeLaunch())
	if err != nil {
		return err
	}

	respLaunch := Launch{}
	_ = json.Unmarshal(buff, &respLaunch)
	if respLaunch.Error() != nil {
		return respLaunch.Error()
	}

	// 2.
	buff, err = app.Request(Remote + app.MakePhoneNumberExist())
	if err != nil {
		return err
	}

	respPhoneNumberExist := PhoneNumberExistResp{}
	_ = json.Unmarshal(buff, &respPhoneNumberExist)
	if respPhoneNumberExist.Error() != nil {
		return respPhoneNumberExist.Error()
	}

	// 3.
	buff, err = app.Request(Remote + app.MakeSMSCodeRequest("sms"))
	if err != nil {
		return err
	}

	respSMSCodeRequest := SMSCodeRequestResp{}
	_ = json.Unmarshal(buff, &respSMSCodeRequest)
	if respSMSCodeRequest.Error() != nil {
		return respSMSCodeRequest.Error()
	}

	// 4.
	fmt.Println("请输入验证码:")

	var smscode string
	_, err = fmt.Scanln(&smscode)
	if err != nil {
		return err
	}

	// 5.
	buff, err = app.Request(Remote + app.MakeSMSVerify(smscode))
	if err != nil {
		return err
	}

	respSMSCode := SMSCodeVerifyResp{}
	_ = json.Unmarshal(buff, &respSMSCode)
	if respSMSCode.Error() != nil {
		return respSMSCode.Error()
	}
	return nil
}
