package forti2versa

import (
	"os"
	"testing"
)

func TestParseAddresses(t *testing.T) {
	text := `
config firewall address
    edit "test-subnet"
        set type ipmask
        set subnet 10.0.0.0 255.255.255.0
        set comment "Test subnet"
    next
    edit "test-fqdn"
        set type fqdn
        set fqdn example.com
    next
    edit "test-range"
        set type iprange
        set start-ip 10.0.0.1
        set end-ip 10.0.0.10
    next
    edit "test-geo"
        set type geography
        set country US
    next
end
`
	p := NewFortiGateParser(text)

	if len(p.Addresses) != 4 {
		t.Fatalf("expected 4 addresses, got %d", len(p.Addresses))
	}
	if p.Addresses["test-subnet"].Subnet != "10.0.0.0 255.255.255.0" {
		t.Error("subnet mismatch")
	}
	if p.Addresses["test-fqdn"].FQDN != "example.com" {
		t.Error("fqdn mismatch")
	}
	if p.Addresses["test-range"].StartIP != "10.0.0.1" {
		t.Error("startip mismatch")
	}
	if p.Addresses["test-geo"].Country != "US" {
		t.Error("country mismatch")
	}
	// Check order
	expected := []string{"test-subnet", "test-fqdn", "test-range", "test-geo"}
	for i, name := range expected {
		if p.AddrOrder[i] != name {
			t.Errorf("order[%d] = %q, want %q", i, p.AddrOrder[i], name)
		}
	}
}

func TestParseServices(t *testing.T) {
	text := `
config firewall service custom
    edit "HTTP"
        set protocol TCP/UDP/SCTP
        set tcp-portrange 80
    next
    edit "DNS"
        set protocol TCP/UDP/SCTP
        set tcp-portrange 53
        set udp-portrange 53
    next
end
`
	p := NewFortiGateParser(text)
	if len(p.Services) != 2 {
		t.Fatalf("expected 2 services, got %d", len(p.Services))
	}
	if p.Services["HTTP"].TCPPortRange != "80" {
		t.Errorf("HTTP tcp port = %q", p.Services["HTTP"].TCPPortRange)
	}
	if p.Services["DNS"].UDPPortRange != "53" {
		t.Errorf("DNS udp port = %q", p.Services["DNS"].UDPPortRange)
	}
}

func TestParsePolicies(t *testing.T) {
	text := `
config firewall policy
    edit 1
        set name "Test-Policy"
        set srcintf "wan1"
        set dstintf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "HTTP" "HTTPS"
        set logtraffic all
        set nat enable
        set utm-status enable
        set av-profile "AV_drop_default"
        set webfilter-profile "Shore_Strict_Allow"
        set ips-sensor "IPS_drop_default"
        set ssl-ssh-profile "deep-inspection"
    next
    edit 2
        set name "Deny-Test"
        set srcintf "port1"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set action deny
        set logtraffic all
    next
end
`
	p := NewFortiGateParser(text)
	if len(p.Policies) != 2 {
		t.Fatalf("expected 2 policies, got %d", len(p.Policies))
	}
	pol := p.Policies[0]
	if pol.Name != "Test-Policy" {
		t.Errorf("name = %q", pol.Name)
	}
	if pol.AVProfile != "AV_drop_default" {
		t.Errorf("av = %q", pol.AVProfile)
	}
	if pol.SSLSSHProfile != "deep-inspection" {
		t.Errorf("ssl = %q", pol.SSLSSHProfile)
	}
	if pol.NAT != "enable" {
		t.Errorf("nat = %q", pol.NAT)
	}
	if len(pol.Service) != 2 {
		t.Errorf("service count = %d", len(pol.Service))
	}

	pol2 := p.Policies[1]
	if pol2.Action != "deny" {
		t.Errorf("policy 2 action = %q", pol2.Action)
	}
}

func TestParseMultilineComment(t *testing.T) {
	text := `
config firewall policy
    edit 14
        set name "Multiline-Comment-Test-Policy"
        set srcintf "port1"
        set dstintf "wan1"
        set srcaddr "LAN"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
        set logtraffic all
        set comments "This is a multiline comment
that continues here
and ends here"
    next
end
`
	p := NewFortiGateParser(text)
	if len(p.Policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(p.Policies))
	}
	pol := p.Policies[0]
	if pol.Comments == "" {
		t.Error("comments should not be empty")
	}
}

func TestParseBackslashContinuation(t *testing.T) {
	lines := preprocess("line1 \\\ncontinued\nline2")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d: %v", len(lines), lines)
	}
	if lines[0] != "line1 continued" {
		t.Errorf("continuation: %q", lines[0])
	}
}

func TestParseWebfilterProfiles(t *testing.T) {
	text := `
config webfilter profile
    edit "Shore_Strict_Allow"
        set comment "Test profile"
        config ftgd-wf
            config filters
                edit 1
                    set category 2
                    set action block
                next
                edit 2
                    set category 52
                    set action monitor
                next
            end
        end
    next
end
`
	p := NewFortiGateParser(text)
	if len(p.WebfilterProfiles) != 1 {
		t.Fatalf("expected 1 profile, got %d", len(p.WebfilterProfiles))
	}
	wf := p.WebfilterProfiles["Shore_Strict_Allow"]
	if len(wf.Categories) != 2 {
		t.Fatalf("expected 2 categories, got %d", len(wf.Categories))
	}
	if wf.Categories[0].ID != 2 || wf.Categories[0].Action != "block" {
		t.Errorf("cat 0: id=%d action=%s", wf.Categories[0].ID, wf.Categories[0].Action)
	}
}

func TestParseAppListProfiles(t *testing.T) {
	text := `
config application list
    edit "App_Test"
        set comment "Test app control"
        config entries
            edit 1
                set category 2
                set action block
            next
            edit 2
                set category 6 25
                set action block
            next
            edit 3
                set application 15832
                set action block
            next
            edit 4
                set application 33
                set action monitor
            next
        end
    next
    edit "App_Strict"
        set unknown-application-action block
        config entries
            edit 1
                set category 2
                set action block
            next
        end
    next
end
`
	p := NewFortiGateParser(text)
	if len(p.AppListProfiles) != 2 {
		t.Fatalf("app profiles: got %d, want 2", len(p.AppListProfiles))
	}

	prof := p.AppListProfiles["App_Test"]
	if prof == nil {
		t.Fatal("App_Test not found")
	}
	if prof.Comment != "Test app control" {
		t.Errorf("comment: got %q", prof.Comment)
	}
	if len(prof.Entries) != 4 {
		t.Fatalf("entries: got %d, want 4", len(prof.Entries))
	}
	// entry 0: single category
	if len(prof.Entries[0].Category) != 1 || prof.Entries[0].Category[0] != 2 {
		t.Errorf("entry 0 category: got %v", prof.Entries[0].Category)
	}
	// entry 1: multi category
	if len(prof.Entries[1].Category) != 2 || prof.Entries[1].Category[0] != 6 || prof.Entries[1].Category[1] != 25 {
		t.Errorf("entry 1 categories: got %v", prof.Entries[1].Category)
	}
	// entry 2: specific app
	if prof.Entries[2].Application != 15832 || prof.Entries[2].Action != "block" {
		t.Errorf("entry 2: got app=%d action=%s", prof.Entries[2].Application, prof.Entries[2].Action)
	}
	// entry 3: monitor
	if prof.Entries[3].Action != "monitor" {
		t.Errorf("entry 3 action: got %q", prof.Entries[3].Action)
	}

	strict := p.AppListProfiles["App_Strict"]
	if strict.UnknownApplicationAction != "block" {
		t.Errorf("unknown-application-action: got %q", strict.UnknownApplicationAction)
	}
}

func TestFullParseFixture(t *testing.T) {
	data, err := os.ReadFile("testdata/source-forti-config.conf")
	if err != nil {
		t.Skip("testdata not available")
	}
	p := NewFortiGateParser(string(data))

	if len(p.Addresses) != 35 {
		t.Errorf("addresses: got %d, want 35", len(p.Addresses))
	}
	if len(p.AddrGroups) != 14 {
		t.Errorf("addr groups: got %d, want 14", len(p.AddrGroups))
	}
	if len(p.Services) != 25 {
		t.Errorf("services: got %d, want 25", len(p.Services))
	}
	if len(p.SvcGroups) != 11 {
		t.Errorf("svc groups: got %d, want 11", len(p.SvcGroups))
	}
	if len(p.WebfilterProfiles) != 4 {
		t.Errorf("webfilter profiles: got %d, want 4", len(p.WebfilterProfiles))
	}
	if len(p.AppListProfiles) != 2 {
		t.Errorf("app list profiles: got %d, want 2", len(p.AppListProfiles))
	}
	if len(p.Policies) != 26 {
		t.Errorf("policies: got %d, want 26", len(p.Policies))
	}
	if len(p.SSLSSHProfiles) != 3 {
		t.Errorf("ssl-ssh profiles: got %d, want 3", len(p.SSLSSHProfiles))
	}
	if len(p.URLFilters) != 2 {
		t.Errorf("url filters: got %d, want 2", len(p.URLFilters))
	}
}

func TestParseWildcardFQDN(t *testing.T) {
	text := `
config firewall wildcard-fqdn custom
    edit "adobe"
        set wildcard-fqdn "*.adobe.com"
    next
    edit "microsoft"
        set wildcard-fqdn "*.microsoft.com"
    next
end
`
	p := NewFortiGateParser(text)
	if len(p.WildcardFQDNs) != 2 {
		t.Fatalf("expected 2 wildcard-fqdns, got %d", len(p.WildcardFQDNs))
	}
	if p.WildcardFQDNs["adobe"].WildcardFQDN != "*.adobe.com" {
		t.Errorf("adobe: got %q", p.WildcardFQDNs["adobe"].WildcardFQDN)
	}
	if p.WFQDNOrder[0] != "adobe" || p.WFQDNOrder[1] != "microsoft" {
		t.Errorf("order: got %v", p.WFQDNOrder)
	}
}

func TestParseSSLSSHProfile(t *testing.T) {
	text := `
config firewall ssl-ssh-profile
    edit "deep-inspection"
        set ssl-exempt-categories 72 7
    next
    edit "SSL_Inspection"
        config ssl-exempt
            edit 1
                set fortiguard-category 140
            next
            edit 2
                set type wildcard-fqdn
                set wildcard-fqdn "adobe"
            next
        end
    next
end
`
	p := NewFortiGateParser(text)
	if len(p.SSLSSHProfiles) != 2 {
		t.Fatalf("expected 2 profiles, got %d", len(p.SSLSSHProfiles))
	}

	deep := p.SSLSSHProfiles["deep-inspection"]
	if len(deep.ExemptCats) != 2 || deep.ExemptCats[0] != 72 || deep.ExemptCats[1] != 7 {
		t.Errorf("deep-inspection exempt cats: got %v", deep.ExemptCats)
	}

	ssl := p.SSLSSHProfiles["SSL_Inspection"]
	if len(ssl.Exemptions) != 2 {
		t.Fatalf("SSL_Inspection exemptions: got %d", len(ssl.Exemptions))
	}
	if ssl.Exemptions[0].FortiguardCategory != 140 {
		t.Errorf("exemption 0 cat: got %d", ssl.Exemptions[0].FortiguardCategory)
	}
	if ssl.Exemptions[1].Type != "wildcard-fqdn" || ssl.Exemptions[1].WildcardFQDN != "adobe" {
		t.Errorf("exemption 1: type=%q wfqdn=%q", ssl.Exemptions[1].Type, ssl.Exemptions[1].WildcardFQDN)
	}
}

func TestParseURLFilterTable(t *testing.T) {
	text := `
config webfilter urlfilter
    edit 1
        set name "Blocked_URLs"
        config entries
            edit 1
                set url "*facebook.com"
                set type wildcard
                set action block
            next
            edit 2
                set url "gambling.com"
                set type simple
                set action block
            next
            edit 3
                set url "*.safe-site.com"
                set type wildcard
                set action exempt
            next
        end
    next
end
`
	p := NewFortiGateParser(text)
	if len(p.URLFilters) != 1 {
		t.Fatalf("expected 1 filter table, got %d", len(p.URLFilters))
	}
	table := p.URLFilters[1]
	if table.Name != "Blocked_URLs" {
		t.Errorf("name: got %q", table.Name)
	}
	if len(table.Entries) != 3 {
		t.Fatalf("entries: got %d", len(table.Entries))
	}
	if table.Entries[0].URL != "*facebook.com" || table.Entries[0].Type != "wildcard" || table.Entries[0].Action != "block" {
		t.Errorf("entry 0: %+v", table.Entries[0])
	}
	if table.Entries[2].Action != "exempt" {
		t.Errorf("entry 2 action: got %q", table.Entries[2].Action)
	}
}

func TestParseOnetimeSchedule(t *testing.T) {
	text := `
config firewall schedule onetime
    edit "Physical Inventory Schedule"
        set start 00:01 2019/10/11
        set end 23:59 2019/10/28
    next
end
`
	p := NewFortiGateParser(text)
	if len(p.OnetimeSchedules) != 1 {
		t.Fatalf("expected 1 schedule, got %d", len(p.OnetimeSchedules))
	}
	sched := p.OnetimeSchedules["Physical Inventory Schedule"]
	if sched.Start != "00:01 2019/10/11" {
		t.Errorf("start: got %q", sched.Start)
	}
	if sched.End != "23:59 2019/10/28" {
		t.Errorf("end: got %q", sched.End)
	}
}

func TestParseIPSSensor(t *testing.T) {
	text := `
config ips sensor
    edit "IPS_drop_default"
        set comment "Block critical and high"
        config entries
            edit 1
                set severity critical high
                set action drop
            next
            edit 2
                set severity medium
                set action reset
            next
            edit 3
                set severity low info
                set action pass
            next
        end
    next
    edit "IPS_monitor"
        config entries
            edit 1
                set severity critical high medium low info
                set action pass
            next
        end
    next
end
`
	p := NewFortiGateParser(text)
	if len(p.IPSSensors) != 2 {
		t.Fatalf("expected 2 IPS sensors, got %d", len(p.IPSSensors))
	}

	sensor := p.IPSSensors["IPS_drop_default"]
	if sensor == nil {
		t.Fatal("IPS_drop_default not found")
	}
	if sensor.Comment != "Block critical and high" {
		t.Errorf("comment: got %q", sensor.Comment)
	}
	if len(sensor.Entries) != 3 {
		t.Fatalf("entries: got %d, want 3", len(sensor.Entries))
	}
	// Entry 0: critical + high -> drop
	e0 := sensor.Entries[0]
	if len(e0.Severities) != 2 || e0.Severities[0] != "critical" || e0.Severities[1] != "high" {
		t.Errorf("entry 0 severities: got %v", e0.Severities)
	}
	if e0.Action != "drop" {
		t.Errorf("entry 0 action: got %q", e0.Action)
	}
	// Entry 1: medium -> reset
	e1 := sensor.Entries[1]
	if len(e1.Severities) != 1 || e1.Severities[0] != "medium" {
		t.Errorf("entry 1 severities: got %v", e1.Severities)
	}
	if e1.Action != "reset" {
		t.Errorf("entry 1 action: got %q", e1.Action)
	}

	// Monitor sensor: all pass
	monitor := p.IPSSensors["IPS_monitor"]
	if len(monitor.Entries) != 1 {
		t.Fatalf("monitor entries: got %d", len(monitor.Entries))
	}
	if monitor.Entries[0].Action != "pass" {
		t.Errorf("monitor action: got %q", monitor.Entries[0].Action)
	}
}
