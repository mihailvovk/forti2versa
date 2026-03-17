package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	forti2versa "forti2versa"
)

func main() {
	configPath := flag.String("c", "converter_config.json", "Path to converter config JSON")
	outputPath := flag.String("o", "", "Output Versa config file (default: <template_name>.cfg)")
	reportPath := flag.String("r", "", "Output report file (default: <template_name>_report.txt)")
	templateName := flag.String("t", "", "Versa template name (overrides config file)")
	tenantName := flag.String("n", "", "Versa tenant/org name (overrides config file)")
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Usage: forti2versa <input> [-c config.json] [-o output.cfg] [-r report.txt] [-t template] [-n tenant]")
		os.Exit(1)
	}
	inputPath := flag.Arg(0)

	// Load config
	config := forti2versa.DefaultConfig()
	configData, err := os.ReadFile(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Config file not found: %s\nUsing default configuration.\n", *configPath)
	} else {
		if err := json.Unmarshal(configData, config); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing config: %v\n", err)
			os.Exit(1)
		}
	}

	// CLI overrides
	if *templateName != "" {
		config.TemplateName = *templateName
	}
	if *tenantName != "" {
		config.OrgName = *tenantName
	}
	config.EnsureMaps()

	// Load FG config
	fgText, err := os.ReadFile(inputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
		os.Exit(1)
	}

	// Parse
	fg := forti2versa.NewFortiGateParser(string(fgText))
	fmt.Printf("Parsed: %d addresses, %d wildcard-fqdns, %d address groups, %d services, %d service groups, %d webfilter profiles, %d app-control profiles, %d ssl-ssh profiles, %d url-filter tables, %d onetime schedules, %d policies\n",
		len(fg.Addresses), len(fg.WildcardFQDNs), len(fg.AddrGroups), len(fg.Services), len(fg.SvcGroups),
		len(fg.WebfilterProfiles), len(fg.AppListProfiles), len(fg.SSLSSHProfiles),
		len(fg.URLFilters), len(fg.OnetimeSchedules), len(fg.Policies))

	// Convert
	converter := forti2versa.NewVersaConverter(fg, config)
	versaOutput := converter.Convert()

	// Write output
	outPath := *outputPath
	if outPath == "" {
		outPath = config.TemplateName + ".cfg"
	}
	if err := os.WriteFile(outPath, []byte(versaOutput+"\n"), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing output: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Versa config written to: %s\n", outPath)

	// Write report
	repPath := *reportPath
	if repPath == "" {
		repPath = config.TemplateName + "_report.txt"
	}
	if err := os.WriteFile(repPath, []byte(converter.Report.Render()), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing report: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Conversion report written to: %s\n", repPath)

	// Write structured (curly-brace) format for Director
	structuredOutput := forti2versa.ConvertToStructured(versaOutput)
	dirPath := config.TemplateName + "_4director.cfg"
	if err := os.WriteFile(dirPath, []byte(structuredOutput), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing structured output: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Structured config written to: %s\n", dirPath)
}
