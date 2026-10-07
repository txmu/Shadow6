package main

import "testing"

func TestStrictConfigJSONBoundaries(t *testing.T) {
	for _, raw := range []string{
		`{"version":1,"version":1}`,
		`{"version":1} {}`,
		`{"version":NaN}`,
		`{"version":1.5}`,
		`{"version":9007199254740992}`,
		`{"role":"\ud800"}`,
		`{"role":"\u0000"}`,
		`{"ROLE":"client"}`,
	} {
		var target Config
		if err := strictConfigJSON([]byte(raw), &target); err == nil {
			t.Fatalf("accepted ambiguous configuration: %s", raw)
		}
	}
}
