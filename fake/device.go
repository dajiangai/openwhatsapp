package fake

type Apple struct {
	Production  string
	DeviceName  string
	OSVersion   string
	BuildNumber string
	Darwin      string
	CFNetwork   string
	Language    string
	Country     string
	MCC         string
	MNC         string
}

func NewApple() Apple {
	fake := randFakeDevice()

	return Apple{
		Production:  fake.Name,
		OSVersion:   fake.OSVersion,
		BuildNumber: fake.BuildNumber,
		Darwin:      fake.Darwin,
		CFNetwork:   fake.CFNetwork,
		Language:    "en",
		MCC:         "000",
		MNC:         "000",
	}
}
