package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestSharedPortableJSONConformance(t *testing.T) {
	raw, err := os.ReadFile("../Tools/strict_json_conformance.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Schema string `json:"schema"`
		Cases  []struct {
			ID       string `json:"id"`
			Input    string `json:"input"`
			Accepted bool   `json:"accepted"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.Schema != "shadow6.strict-json-conformance.v1" {
		t.Fatal("unknown corpus schema")
	}
	for _, item := range corpus.Cases {
		t.Run(item.ID, func(t *testing.T) {
			data := []byte(item.Input)
			err := validateStrictJSON(data, nil)
			if err == nil {
				decoder := json.NewDecoder(bytes.NewReader(data))
				decoder.UseNumber()
				var value any
				err = decoder.Decode(&value)
				if err == nil {
					var out strings.Builder
					err = writePortableJSON(&out, value, 0)
				}
			}
			if (err == nil) != item.Accepted {
				t.Fatalf("accepted=%v, want %v: %v", err == nil, item.Accepted, err)
			}
		})
	}
}
