package fake

import (
	"embed"
	"encoding/json"
	"math/rand"
	"sync"
)

type firmwareTemplate struct {
	Name       string `json:"name"`
	Identifier string `json:"identifier"`
	Firmwares  []struct {
		OSVersion   string `json:"version"`
		BuildNumber string `json:"buildid"`
	} `json:"firmwares"`
}

type userAgentTemplate struct {
	DarwinVersion    string   `json:"DarwinVersion"`
	CFNetworkVersion string   `json:"CFNetworkVersion"`
	IOSVersions      []string `json:"IOSVersions"`
}

type Fake struct {
	Name        string `json:"name"`
	Identifier  string `json:"identifier"`
	OSVersion   string `json:"version"`
	BuildNumber string `json:"buildid"`
	Darwin      string `json:"Darwin"`
	CFNetwork   string `json:"cfNetwork"`
}

var (
	//go:embed firmware.json
	//go:embed useragent-ios.json
	FakeFiles embed.FS
	firmwares []firmwareTemplate
	agents    []userAgentTemplate
	once      sync.Once
)

func randFakeDevice() Fake {
	once.Do(func() {
		buff, err := FakeFiles.ReadFile("firmware.json")
		if err != nil {
			panic("firmware.json not exist")
		}
		_ = json.Unmarshal(buff, &firmwares)

		buff, err = FakeFiles.ReadFile("useragent-ios.json")
		if err != nil {
			panic("useragent-ios.json not exist")
		}
		_ = json.Unmarshal(buff, &agents)
	})

	n := rand.Intn(len(firmwares))
	t := firmwares[n]
	m := rand.Intn(len(t.Firmwares))
	firmware := t.Firmwares[m]

	var ug userAgentTemplate

	for _, ag := range agents {
		for _, os := range ag.IOSVersions {
			if os == firmware.OSVersion {
				ug = ag
				break
			}
		}
	}

	return Fake{
		Name:        t.Name,
		Identifier:  t.Identifier,
		OSVersion:   firmware.OSVersion,
		BuildNumber: firmware.BuildNumber,
		Darwin:      ug.DarwinVersion,
		CFNetwork:   ug.CFNetworkVersion,
	}
}
