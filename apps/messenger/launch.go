package messenger

import "fmt"

type Launch struct {
	Login  string `json:"login"`  // 手机号
	Status string `json:"status"` // 状态
}

// Error .
func (p *Launch) Error() error {
	return nil
}

type ABPropResp struct {
	AbHash string `json:"ab_hash"`
	AbKey  string `json:"ab_key"`
	ExpCfg string `json:"exp_cfg"`
	Login  string `json:"login"`
	Status string `json:"status"`
}

// Error .
func (p *ABPropResp) Error() error {
	return nil
}

func (app *Messenger) MakeLaunch() string {
	return "/v2/exist"
}

func (app *Messenger) MakeABProp() string {
	return "/v2/reg_onboard_abprop?" + fmt.Sprintf("cc=%v&in=%v&rc=%v", app.CountryCode, app.NationalNumber, "0")
}
