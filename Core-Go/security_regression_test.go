package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestSecurityStrictJSON(t *testing.T) {
	for _, input := range []string{
		`{"role":"client","role":"broker"}`,
		`{"role":"client","\u0072ole":"broker"}`,
		`{"Role":"broker"}`,
		`{"agent":{"client_pubkeys":{"a":"first","a":"second"}}}`,
		`{"role":"\ud800"}`,
		"{\"role\":\"\xff\"}",
	} {
		var config Config
		if decodeStrict([]byte(input), &config) == nil {
			t.Errorf("ambiguous or invalid JSON accepted: %q", input)
		}
	}
	var raw json.RawMessage
	if decodeStrict([]byte(strings.Repeat("[", 65)+"0"+strings.Repeat("]", 65)), &raw) == nil {
		t.Error("excessively nested JSON accepted")
	}
	var config Config
	if err := decodeStrict([]byte(`{"role":"broker"}`), &config); err != nil {
		t.Fatal(err)
	}
}

func TestSecurityCrosedPortablePayload(t *testing.T) {
	request := CrosedRequest{Version: 1, ModID: "test", Nonce: strings.Repeat("01", 16), IssuedAt: 1, RequestedLevel: 1}
	for _, payload := range []string{
		`{"x":1.5}`, `{"x":1e2}`, `{"x":9007199254740992}`,
		`{"x":-9007199254740992}`, `{"x":1,"x":2}`, `{"x":"\u0000"}`,
		`{"x":"\ud800"}`, `{} {}`,
		`{"x":"` + strings.Repeat("a", 16385) + `"}`,
		strings.Repeat("[", 17) + "0" + strings.Repeat("]", 17),
	} {
		request.Payload = json.RawMessage(payload)
		if crosedSignedPayload(request) != nil {
			t.Errorf("nonportable signed payload accepted: %.80s", payload)
		}
	}
	// Exact UTF-8 representation emitted by the existing Python request builder.
	canonical := "{\"a\":\"<>&\u2028\u2029你好\",\"z\":9007199254740991}"
	request.Payload = json.RawMessage(canonical)
	digest := sha256.Sum256([]byte(canonical))
	want := "1\ntest\n" + request.Nonce + "\n1\n1\n\n" + hex.EncodeToString(digest[:]) + "\n\n"
	if got := string(crosedSignedPayload(request)); got != want {
		t.Errorf("Crosed canonical signature input differs from portable JSON: %q", got)
	}
}

func FuzzStrictConfigJSON(f *testing.F) {
	for _, input := range []string{`{"role":"broker"}`, `{"role":"a","role":"b"}`,
		`{"role":"\ud800"}`, `{"agent":{"client_pubkeys":{"x":"y"}}}`, `null`, `[]`, `{} {}`} {
		f.Add([]byte(input))
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		var config Config
		if decodeStrict(input, &config) != nil {
			return
		}
		if !json.Valid(input) {
			t.Fatal("accepted invalid JSON")
		}
		encoded, err := json.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
		var roundtrip Config
		if err := decodeStrict(encoded, &roundtrip); err != nil {
			t.Fatalf("accepted configuration cannot be decoded after encoding: %v", err)
		}
	})
}
