package forti2versa

import (
	"encoding/json"
	"os"
	"testing"
)

func TestGoldenVersa(t *testing.T) {
	fgText, err := os.ReadFile("testdata/source-forti-config.conf")
	if err != nil {
		t.Fatalf("reading input: %v", err)
	}
	configData, err := os.ReadFile("testdata/converter_config.json")
	if err != nil {
		t.Fatalf("reading config: %v", err)
	}
	var config Config
	if err := json.Unmarshal(configData, &config); err != nil {
		t.Fatalf("parsing config: %v", err)
	}
	if config.InterfaceZoneMap == nil {
		config.InterfaceZoneMap = make(map[string]string)
	}
	if config.ScheduleMap == nil {
		config.ScheduleMap = make(map[string]string)
	}
	if config.SecurityProfileMap == nil {
		config.SecurityProfileMap = make(map[string]map[string]string)
	}

	fg := NewFortiGateParser(string(fgText))
	converter := NewVersaConverter(fg, &config)
	got := converter.Convert() + "\n"

	golden, err := os.ReadFile("testdata/golden_versa.txt")
	if err != nil {
		t.Fatalf("reading golden: %v", err)
	}

	if got != string(golden) {
		t.Errorf("output differs from golden_versa.txt")
		// Write actual output for diffing
		os.WriteFile("testdata/actual_versa.txt", []byte(got), 0644)
		t.Log("Actual output written to testdata/actual_versa.txt — run: diff testdata/golden_versa.txt testdata/actual_versa.txt")
	}
}

func TestGoldenReport(t *testing.T) {
	fgText, err := os.ReadFile("testdata/source-forti-config.conf")
	if err != nil {
		t.Fatalf("reading input: %v", err)
	}
	configData, err := os.ReadFile("testdata/converter_config.json")
	if err != nil {
		t.Fatalf("reading config: %v", err)
	}
	var config Config
	if err := json.Unmarshal(configData, &config); err != nil {
		t.Fatalf("parsing config: %v", err)
	}
	if config.InterfaceZoneMap == nil {
		config.InterfaceZoneMap = make(map[string]string)
	}
	if config.ScheduleMap == nil {
		config.ScheduleMap = make(map[string]string)
	}
	if config.SecurityProfileMap == nil {
		config.SecurityProfileMap = make(map[string]map[string]string)
	}

	fg := NewFortiGateParser(string(fgText))
	converter := NewVersaConverter(fg, &config)
	converter.Convert()
	got := converter.Report.Render()

	golden, err := os.ReadFile("testdata/golden_report.txt")
	if err != nil {
		t.Fatalf("reading golden report: %v", err)
	}

	if got != string(golden) {
		t.Errorf("report differs from golden_report.txt")
		os.WriteFile("testdata/actual_report.txt", []byte(got), 0644)
		t.Log("Actual report written to testdata/actual_report.txt — run: diff testdata/golden_report.txt testdata/actual_report.txt")
	}
}
