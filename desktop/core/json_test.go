package core

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestStrictJSONRejectsAmbiguousOrMalformedDocuments(t *testing.T) {
	invalid := []string{
		`{"x":1,"x":2}`, `{"a":1,"\u0061":2}`, `{"nested":{"\u005f_proto__":{}}}`,
		`{"prototype":{}}`, `{"constructor":null}`, `{"n":9007199254740992}`, `{"n":-9007199254740992}`,
		`{"n":9007199254740991.5}`, `1e400`, `-1e400`, `01`, `1.`, `+1`, `NaN`, `Infinity`, `undefined`,
		`{"x":1,}`, `[1,]`, `true false`, `{}x`, `{"a" 1}`, `{"a":}`, `{"a":1`,
		`"\u+123"`, `"\u000g"`, `"\x61"`, `"\"`, "\"line\nbreak\"", "\vnull", "\ufeffnull", "\"\xff\"",
		strings.Repeat("[", 33) + "0" + strings.Repeat("]", 33),
	}
	for _, raw := range invalid {
		t.Run(raw, func(t *testing.T) {
			if _, err := StrictJSON([]byte(raw), 262144); CodeOf(err) != "INVALID_INPUT" || err == nil {
				t.Fatalf("accepted malformed JSON %q: %v", raw, err)
			}
		})
	}
	if _, err := StrictJSON([]byte(`"é"`), 3); err == nil {
		t.Fatal("limit counted runes instead of UTF-8 bytes")
	}
}

func TestStrictJSONPreservesPrecisionDepthAndStringSemantics(t *testing.T) {
	for _, raw := range []string{`9007199254740991`, `-9007199254740991`, `1e0`, `1.5`, `-0`, `null`, `true`, `false`, `[]`, `{}`, strings.Repeat("[", 32) + "0" + strings.Repeat("]", 32)} {
		if _, err := StrictJSON([]byte(raw), 262144); err != nil {
			t.Fatalf("rejected %s: %v", raw, err)
		}
	}
	parsed, err := StrictJSON([]byte(`{"n":9007199254740991,"s":"<>&\u2028\u2029\uD83D\uDE00"}`), 1024)
	if err != nil {
		t.Fatal(err)
	}
	object := parsed.(map[string]any)
	if object["n"] != json.Number("9007199254740991") {
		t.Fatalf("number coerced: %#v", object["n"])
	}
	if object["s"] != "<>&\u2028\u2029😀" {
		t.Fatalf("string changed: %#v", object["s"])
	}
	for _, raw := range []string{`"\ud800"`, `"\udfff"`} {
		v, err := StrictJSON([]byte(raw), 32)
		if err != nil {
			t.Fatal(err)
		}
		s := v.(string)
		if len(s) != 3 || stringLength(s) != 1 {
			t.Fatalf("lost lone surrogate: %x", s)
		}
	}
	if _, err := StrictJSON([]byte(`{"\ud800":1,"\ud801":2}`), 128); err != nil {
		t.Fatalf("distinct surrogates collapsed: %v", err)
	}
	if _, err := StrictJSON([]byte(`{"\uD800":1,"\ud800":2}`), 128); err == nil {
		t.Fatal("duplicate surrogate key accepted")
	}
}

func TestDecodeStrictPresenceNullabilityDefaultsAndAtomicity(t *testing.T) {
	type nested struct {
		Count int `json:"count"`
	}
	type shape struct {
		Required     string   `json:"required"`
		Nullable     *string  `json:"nullable,nullable"`
		Optional     *string  `json:"optional,omitempty"`
		Nested       nested   `json:"nested"`
		Array        []string `json:"array"`
		Default      bool     `json:"default" default:"true"`
		DefaultArray []string `json:"defaultArray" default:"[]"`
	}
	valid := `{"required":"present","nullable":null,"nested":{"count":1e0},"array":[]}`
	var result shape
	if err := DecodeStrict([]byte(valid), &result, 1024); err != nil {
		t.Fatal(err)
	}
	if !result.Default || result.DefaultArray == nil || result.Array == nil || result.Nested.Count != 1 {
		t.Fatalf("incorrect defaults or arrays: %#v", result)
	}
	before := result
	for _, raw := range []string{
		strings.Replace(valid, `"required":"present",`, "", 1), strings.Replace(valid, `"nullable":null,`, "", 1),
		strings.Replace(valid, `"array":[]`, `"array":null`, 1), strings.Replace(valid, `"array":[]`, `"array":[null]`, 1),
		strings.Replace(valid, `"count":1e0`, `"count":1.1`, 1), strings.Replace(valid, `"count":1e0`, `"count":1,"extra":true`, 1),
		strings.Replace(valid, `"array":[]`, `"array":[],"optional":null`, 1), strings.Replace(valid, `"array":[]`, `"array":[],"default":null`, 1),
		strings.Replace(valid, `"array":[]`, `"array":[],"Default":true`, 1),
	} {
		if err := DecodeStrict([]byte(raw), &result, 1024); err == nil {
			t.Fatalf("accepted invalid shape: %s", raw)
		}
		if !reflect.DeepEqual(before, result) {
			t.Fatalf("failed decoding partially changed destination: %#v", result)
		}
	}
	if err := DecodeStrict([]byte(valid), result, 1024); err == nil {
		t.Fatal("accepted non-pointer output")
	}
}

type validatedChild struct {
	Value int `json:"value"`
}

func (v *validatedChild) Validate() error { return invalidUnless(v.Value == 7) }
func TestDecodeStrictCallsNestedPointerValidators(t *testing.T) {
	var value struct {
		Children []validatedChild `json:"children"`
	}
	if err := DecodeStrict([]byte(`{"children":[{"value":8}]}`), &value, 1024); err == nil {
		t.Fatal("skipped nested validator")
	}
	if err := DecodeStrict([]byte(`{"children":[{"value":7}]}`), &value, 1024); err != nil {
		t.Fatal(err)
	}
}
