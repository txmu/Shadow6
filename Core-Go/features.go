package main

import "encoding/json"

const coreVersion = "1.1.0"

type FeatureReport struct {
	Core               string   `json:"core"`
	Version            string   `json:"version"`
	CrosedCompiled     bool     `json:"crosed_compiled"`
	CrosedMaxLevel     int      `json:"crosed_max_level"`
	AppTransport       bool     `json:"app_transport"`
	QubesIsolation     bool     `json:"qubes_isolation"`
	GateCompiled       bool     `json:"gate_compiled"`
	GateEnabledDefault bool     `json:"gate_enabled_by_default"`
	UTF8               bool     `json:"utf8"`
	CrosedCapabilities []string `json:"crosed_capabilities"`
}

func compiledFeatureReport() FeatureReport {
	level := compiledCrosedLevel()
	capabilities := []string{}
	for capability, required := range crosedCapabilityLevels {
		if required <= level && (capability != "transport.application" || compiledAppTransport()) {
			capabilities = append(capabilities, capability)
		}
	}
	sortStrings(capabilities)
	return FeatureReport{
		Core: "shadow6-go", Version: coreVersion, CrosedCompiled: level > 0,
		CrosedMaxLevel: level, AppTransport: compiledAppTransport(),
		QubesIsolation: compiledQubesIsolation(), GateCompiled: true, GateEnabledDefault: false, UTF8: true,
		CrosedCapabilities: capabilities,
	}
}

func marshalFeatureReport() ([]byte, error) {
	return json.Marshal(compiledFeatureReport())
}

func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}
