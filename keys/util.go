package keys

import (
	"strings"
)

const (
	cert = "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"
)

//func tlsConfig() *tls.Config {
//	raw, err := base64.RawStdEncoding.DecodeString(cert)
//	if err != nil {
//		panic(err)
//	}
//
//	rd := brotli.NewReader(bytes.NewBuffer(raw))
//	rb, _ := ioutil.ReadAll(rd)
//
//	pool := x509.NewCertPool()
//	pool.AppendCertsFromPEM(rb)
//
//	return &tls.Config{RootCAs: pool, InsecureSkipVerify: true}
//}

func GenURLParams(content []byte) string {
	newContent := strings.ReplaceAll(string(content), "{", "")
	newContent = strings.ReplaceAll(newContent, "}", "")
	newContent = strings.ReplaceAll(newContent, "\"", "")
	newContent = strings.ReplaceAll(newContent, ":", "=")
	newContent = strings.ReplaceAll(newContent, ",", "&")
	return newContent
}

func URLEncode(content string) string {
	ret := escape(content, 1)
	return ret
}

type encoding int

const (
	encodePath encoding = 1 + iota
	encodePathSegment
	encodeHost
	encodeZone
	encodeUserPassword
	encodeQueryComponent
	encodeFragment
)

const upperhex = "0123456789ABCDEF"

func escape(s string, mode encoding) string {
	spaceCount, hexCount := 0, 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if shouldEscape(c, mode) {
			if c == ' ' && mode == encodeQueryComponent {
				spaceCount++
			} else {
				hexCount++
			}
		}
	}

	if spaceCount == 0 && hexCount == 0 {
		return s
	}

	var buf [64]byte
	var t []byte

	required := len(s) + 2*hexCount
	if required <= len(buf) {
		t = buf[:required]
	} else {
		t = make([]byte, required)
	}

	if hexCount == 0 {
		copy(t, s)
		for i := 0; i < len(s); i++ {
			if s[i] == ' ' {
				t[i] = '+'
			}
		}
		return string(t)
	}

	j := 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == ' ' && mode == encodeQueryComponent:
			t[j] = '+'
			j++
		case shouldEscape(c, mode):
			t[j] = '%'
			t[j+1] = upperhex[c>>4]
			t[j+2] = upperhex[c&15]
			j += 3
		default:
			t[j] = s[i]
			j++
		}
	}
	return string(t)
}

func shouldEscape(c byte, mode encoding) bool {
	// Everything else must be escaped.
	return true
}
