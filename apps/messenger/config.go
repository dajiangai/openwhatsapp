package messenger

import (
	"fmt"
	"github.com/dajiangai/openwhatsapp/fake"
	"strings"
)

const (
	Remote      = "https://v.whatsapp.net"
	WSMessenger = "WhatsApp Message"
	WSUrl       = "g.whatsapp.net:5222"
	UserAgent   = "WhatsApp/%s iOS/%v Device/%v"

	// WSVersion  WABuildVersion
	WSVersion = 0x02170C4C

	//WSHandshakeHeader    = 0x2054157
	//WSEdge               = "45440001000004" // ED01004

	NoiseFullPattern     = "Noise_XX_25519_AESGCM_SHA256\x00\x00\x00\x00"
	NoiseResumePattern   = "Noise_IK_25519_AESGCM_SHA256\x00\x00\x00\x00"
	NoiseCallbackPattern = "Noise_XXfallback_25519_AESGCM_SHA256"
)

var (
	// [WARegistrationURLBuilder verificationCodeRequestURLWithMethod:mcc:mnc:jailbroken:context:]
	// aesDecodeWithPassphrase
	AESPassword = "0a1mLfGUIBVrMKF1RdvLI5lkRBvof6vn0fD2QRSM"

	// -[WAPreparedRegistrationURL urlWithTokenArray:]
	// 这里有用到的一个全局数组
	AESCurve25519PublicKey = []byte{
		0x8e, 0x8c, 0x0f, 0x74, 0xc3, 0xeb, 0xc5, 0xd7,
		0xa6, 0x86, 0x5c, 0x6c, 0x3c, 0x84, 0x38, 0x56,
		0xb0, 0x61, 0x21, 0xcc, 0xe8, 0xea, 0x77, 0x4d,
		0x22, 0xfb, 0x6f, 0x12, 0x25, 0x12, 0x30, 0x2d,
	}

	// BuildHash SharedModules WABuildHash
	BuildHash = "425a323f915c94fbf1d52c1833e60c1e"

	// CommitHash SharedModules WABuildCommitHash
	CommitHash = "7b361b5cf34"
)

func AppVersion() (string, []uint32) {
	primary := WSVersion & 0xFF000000 >> 24
	secondary := WSVersion & 0x00FF0000 >> 16
	tertiary := WSVersion & 0x0000FF00 >> 8
	quaternary := WSVersion & 0x000000FF
	return fmt.Sprintf("%d.%d.%d.%d", primary, secondary, tertiary, quaternary),
		[]uint32{uint32(primary), uint32(secondary), uint32(tertiary), uint32(quaternary)}
}

func UserAgentString(device fake.Apple) string {
	product := device.Production
	desc := strings.ReplaceAll(product, " ", "_")

	ver, _ := AppVersion()
	return fmt.Sprintf(UserAgent, ver, device.OSVersion, desc)
}

func HandShakeHeader() string {
	//buff := utils.IntToLittleEndianBytes(WSHandshakeHeader)
	//return string(buff)
	return ""
}

func Edge() string {
	//return WSEdge
	return ""
}

func GenerateCurve25519Signature() []byte {
	//todo:try
	return nil
}
