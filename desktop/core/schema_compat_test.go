package core

import (
	"encoding/json"
	"os"
	"testing"
)

func TestSchemaTypeScriptOracle(t *testing.T) {
	data, err := os.ReadFile("testdata/schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Name   string `json:"name"`
			Schema string `json:"schema"`
			Raw    string `json:"raw"`
			Valid  bool   `json:"valid"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Cases) == 0 {
		t.Fatal("missing reference cases")
	}
	for _, test := range fixture.Cases {
		t.Run(test.Name, func(t *testing.T) {
			var out any
			switch test.Schema {
			case "account":
				out = &Account{}
			case "build":
				out = &BuildConfig{}
			case "command":
				out = &Command{}
			case "policy":
				out = &Policy{}
			case "preferences":
				out = &Preferences{}
			case "refresh":
				out = &Refresh{}
			default:
				t.Fatalf("unknown reference schema %q", test.Schema)
			}
			err := DecodeStrict([]byte(test.Raw), out, 262144)
			if (err == nil) != test.Valid {
				t.Fatalf("Go valid=%v, TypeScript valid=%v, error=%v", err == nil, test.Valid, err)
			}
			if test.Schema == "command" {
				_, err := ParseCommand([]byte(test.Raw))
				if (err == nil) != test.Valid {
					t.Fatalf("Command bridge valid=%v, TypeScript valid=%v, error=%v", err == nil, test.Valid, err)
				}
			}
		})
	}
}
