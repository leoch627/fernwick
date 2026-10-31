package core

import (
	"encoding/json"
	"testing"
)

// This scanner processes signed remote data before reflection-based decoding.
// Any accepted byte sequence must at least be syntactically valid JSON; stricter
// duplicate-key, depth and numeric constraints are covered by table tests.
func FuzzStrictJSONSyntax(f *testing.F) {
	for _, seed := range []string{
		`{"a":[1,true,null,"text"]}`, `{"a":1,"\u0061":2}`, `"\ud800"`,
		`"\ud83d\ude00"`, `-1.25e2`, `[[]]`, `{"constructor":{}}`, `"\u+123"`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if _, err := StrictJSON(data, 4096); err == nil && !json.Valid(data) {
			t.Fatal("strict scanner accepted invalid JSON syntax")
		}
		var command Command
		// Arbitrary shapes must fail without panics or partially changing output.
		if err := DecodeStrict(data, &command, 4096); err != nil && command.Type != "" {
			t.Fatal("failed decode modified destination")
		}
	})
}
