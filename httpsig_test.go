package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"net/url"
	"testing"
)

func TestHTTPSigKnownAnswers(t *testing.T) {
	// RFC 9530 / RFC 9421 Appendix B.2: the test request body.
	body := []byte(`{"hello": "world"}`)
	if got := contentDigest(body, "sha-512"); got != "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:" {
		t.Errorf("content digest: %s", got)
	}
	// RFC 9421 B.2.6: Ed25519 over date, @method, @path, @authority, content-type, content-length.
	u, _ := url.Parse("https://example.com/foo?param=Value&Pet=dog")
	req := &sigRequest{Method: "POST", URL: u, Headers: map[string]string{"date": "Tue, 20 Apr 2021 02:07:55 GMT", "content-type": "application/json", "content-length": "18"}}
	comps := []string{"date", "@method", "@path", "@authority", "content-type", "content-length"}
	sp := signatureParams(comps, [][2]string{{"created", "1618884473"}, {"keyid", "test-key-ed25519"}})
	base, err := signatureBase(req, comps, sp)
	if err != nil {
		t.Fatal(err)
	}
	want := "\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n\"@method\": POST\n\"@path\": /foo\n\"@authority\": example.com\n\"content-type\": application/json\n\"content-length\": 18\n" +
		"\"@signature-params\": (\"date\" \"@method\" \"@path\" \"@authority\" \"content-type\" \"content-length\");created=1618884473;keyid=\"test-key-ed25519\""
	if base != want {
		t.Errorf("signature base:\n%s\nwant:\n%s", base, want)
	}
	x, _ := b64urlDecode("JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs")
	d, _ := b64urlDecode("n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU")
	rfcSig, _ := base64.StdEncoding.DecodeString("wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==")
	if err := httpsigVerify(ed25519.PublicKey(x), "ed25519", []byte(base), rfcSig); err != nil {
		t.Errorf("the RFC's signature does not verify over our base: %v", err)
	}
	ours, _ := httpsigSign(ed25519.NewKeyFromSeed(d), "ed25519", []byte(base))
	if base64.StdEncoding.EncodeToString(ours) != base64.StdEncoding.EncodeToString(rfcSig) {
		t.Errorf("our Ed25519 signature differs from the RFC's")
	}
}
