package forti2versa

import (
	"strings"
	"testing"
)

func newTestConfig() *Config {
	return &Config{
		TemplateName: "T",
		OrgName:      "O",
		PolicyName:   "P",
		InterfaceZoneMap: map[string]string{
			"wan1":  "WAN-Zone",
			"port1": "LAN-Zone",
		},
		SkipOrphans: true,
		ScheduleMap: map[string]string{},
		SecurityProfileMap: map[string]map[string]string{
			"av-profile":       {"AV_test": "Scan Web Traffic"},
			"ips-sensor":       {"IPS_test": "Versa Recommended Profile"},
			"webfilter-profile": {"WF_mapped": "corporate"},
			"dnsfilter-profile": {},
		},
	}
}

func TestConvertSimpleAllow(t *testing.T) {
	text := `
config firewall address
    edit "src-net"
        set type ipmask
        set subnet 10.0.0.0 255.255.255.0
    next
    edit "dst-net"
        set type ipmask
        set subnet 172.16.0.0 255.255.0.0
    next
end
config firewall service custom
    edit "HTTP"
        set protocol TCP/UDP/SCTP
        set tcp-portrange 80
    next
end
config firewall policy
    edit 1
        set name "Allow-Web"
        set srcintf "port1"
        set dstintf "wan1"
        set srcaddr "src-net"
        set dstaddr "dst-net"
        set action accept
        set schedule "always"
        set service "HTTP"
        set logtraffic all
    next
end
`
	p := NewFortiGateParser(text)
	c := NewVersaConverter(p, newTestConfig())
	out := c.Convert()

	// Should have address objects + rule
	if !strings.Contains(out, "addresses address src-net ipv4-prefix 10.0.0.0/24") {
		t.Error("missing src-net address")
	}
	if !strings.Contains(out, "set action allow") {
		t.Error("missing allow action")
	}
	if !strings.Contains(out, "set set-type public") {
		t.Error("missing set-type public")
	}
	if !strings.Contains(out, "set lef event both") {
		t.Error("missing lef event both for logtraffic=all")
	}
}

func TestConvertDeny(t *testing.T) {
	text := `
config firewall policy
    edit 1
        set name "Deny-All"
        set srcintf "wan1"
        set dstintf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set action deny
        set logtraffic all
    next
end
`
	p := NewFortiGateParser(text)
	c := NewVersaConverter(p, newTestConfig())
	out := c.Convert()

	if !strings.Contains(out, "set action deny") {
		t.Error("missing deny action")
	}
}

func TestConvertGeography(t *testing.T) {
	text := `
config firewall address
    edit "GEO_US"
        set type geography
        set country US
    next
end
config firewall policy
    edit 1
        set name "Geo-Test"
        set srcintf "wan1"
        set dstintf "port1"
        set srcaddr "GEO_US"
        set dstaddr "all"
        set action deny
        set logtraffic all
    next
end
`
	p := NewFortiGateParser(text)
	c := NewVersaConverter(p, newTestConfig())
	out := c.Convert()

	if !strings.Contains(out, "match source region [ US ]") {
		t.Error("missing geography region match")
	}
}

func TestConvertIPRange(t *testing.T) {
	text := `
config firewall address
    edit "range1"
        set type iprange
        set start-ip 10.0.0.0
        set end-ip 10.0.0.255
    next
end
config firewall policy
    edit 1
        set name "Range-Test"
        set srcintf "port1"
        set dstintf "wan1"
        set srcaddr "range1"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
        set logtraffic all
    next
end
`
	p := NewFortiGateParser(text)
	cfg := newTestConfig()
	cfg.SkipOrphans = false
	c := NewVersaConverter(p, cfg)
	out := c.Convert()

	// Single CIDR range should emit an address, not a group
	if !strings.Contains(out, "addresses address range1 ipv4-prefix 10.0.0.0/24") {
		t.Error("missing range address")
	}
}

func TestConvertSecurityProfiles(t *testing.T) {
	text := `
config firewall policy
    edit 1
        set name "Profile-Test"
        set srcintf "port1"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
        set logtraffic all
        set utm-status enable
        set av-profile "AV_test"
        set ips-sensor "IPS_test"
        set webfilter-profile "WF_mapped"
    next
end
`
	p := NewFortiGateParser(text)
	c := NewVersaConverter(p, newTestConfig())
	out := c.Convert()

	if !strings.Contains(out, `predefined-av-profile "Scan Web Traffic"`) {
		t.Error("missing AV profile")
	}
	if !strings.Contains(out, `predefined-ips-profile "Versa Recommended Profile"`) {
		t.Error("missing IPS profile")
	}
	if !strings.Contains(out, `url-filtering predefined corporate`) {
		t.Error("missing url-filtering profile")
	}
}

func TestConvertUserGroups(t *testing.T) {
	text := `
config firewall policy
    edit 1
        set name "User-Test"
        set srcintf "port1"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
        set logtraffic all
        set groups "TestGroup"
        set users "testuser"
    next
end
`
	p := NewFortiGateParser(text)
	c := NewVersaConverter(p, newTestConfig())
	out := c.Convert()

	if !strings.Contains(out, "local-database status enabled") {
		t.Error("user db should be enabled when users/groups present")
	}
	if !strings.Contains(out, "group-list [ TestGroup ]") {
		t.Error("missing group-list")
	}
	if !strings.Contains(out, "user-list [ testuser ]") {
		t.Error("missing user-list")
	}
	if !strings.Contains(out, "user-type selected") {
		t.Error("missing user-type selected")
	}
}

func TestConvertNoUsers(t *testing.T) {
	text := `
config firewall policy
    edit 1
        set name "No-User-Test"
        set srcintf "port1"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
        set logtraffic all
    next
end
`
	p := NewFortiGateParser(text)
	c := NewVersaConverter(p, newTestConfig())
	out := c.Convert()

	if !strings.Contains(out, "local-database status disabled") {
		t.Error("user db should be disabled when no users/groups")
	}
	if !strings.Contains(out, "user-type any") {
		t.Error("missing user-type any")
	}
}

func TestConvertPredefinedServices(t *testing.T) {
	text := `
config firewall service custom
    edit "HTTP"
        set protocol TCP
        set tcp-portrange 80
    next
    edit "HTTPS"
        set protocol TCP
        set tcp-portrange 443
    next
    edit "DNS"
        set protocol TCP UDP
        set tcp-portrange 53
        set udp-portrange 53
    next
    edit "CustomPort"
        set protocol TCP
        set tcp-portrange 9999
    next
end
config firewall policy
    edit 1
        set name "Mixed-Services"
        set srcintf "port1"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "HTTP" "HTTPS" "CustomPort"
        set logtraffic all
    next
    edit 2
        set name "DNS-Only"
        set srcintf "port1"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "DNS"
        set logtraffic all
    next
    edit 3
        set name "SSH-Builtin"
        set srcintf "port1"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "SSH"
        set logtraffic all
    next
end
`
	p := NewFortiGateParser(text)
	cfg := newTestConfig()
	cfg.SkipOrphans = false
	c := NewVersaConverter(p, cfg)
	out := c.Convert()

	// HTTP/HTTPS should use predefined, CustomPort stays custom
	if !strings.Contains(out, "predefined-services-list [ http https ]") {
		t.Error("mixed policy should have predefined http https")
	}
	if !strings.Contains(out, "services-list [ CustomPort ]") {
		t.Error("mixed policy should have custom CustomPort")
	}

	// No custom service objects for HTTP, HTTPS, DNS
	if strings.Contains(out, "services service HTTP protocol") {
		t.Error("HTTP should not create custom service object")
	}
	if strings.Contains(out, "services service DNS-TCP") {
		t.Error("DNS should not create custom TCP service object")
	}

	// DNS maps to single "domain" predefined
	if !strings.Contains(out, "predefined-services-list [ domain ]") {
		t.Error("DNS policy should use predefined domain")
	}

	// SSH (not in config firewall service custom) maps to predefined
	if !strings.Contains(out, "predefined-services-list [ ssh ]") {
		t.Error("SSH builtin should use predefined ssh")
	}
}

func TestConvertDecryption(t *testing.T) {
	text := `
config firewall policy
    edit 1
        set name "Decrypt-Test"
        set srcintf "port1"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
        set logtraffic all
        set ssl-ssh-profile "deep-inspection"
    next
end
`
	p := NewFortiGateParser(text)
	c := NewVersaConverter(p, newTestConfig())
	out := c.Convert()

	if !strings.Contains(out, "decrypt-profile ssl-decrypt-profile") {
		t.Error("missing decrypt profile")
	}
	if !strings.Contains(out, "decrypt-except-certpinned") {
		t.Error("missing decrypt action")
	}
	if !strings.Contains(out, "predefined-services-list [ https ]") {
		t.Error("missing https service in decrypt rule")
	}
	if !strings.Contains(out, "certificate \"{$v_") {
		t.Error("missing certificate template variable in decrypt profile")
	}
	if !strings.Contains(out, "ca-chain \"{$v_") {
		t.Error("missing ca-chain template variable in decrypt profile")
	}
	if !strings.Contains(out, "ocsp enabled disabled") {
		t.Error("missing OCSP settings in decrypt profile")
	}
	if !strings.Contains(out, "ocsp response-timeout 5") {
		t.Error("missing OCSP response-timeout in decrypt profile")
	}
	if !strings.Contains(out, "ocsp ocsp-action drop") {
		t.Error("missing OCSP action in decrypt profile")
	}
}

func TestConvertWildcardFQDN(t *testing.T) {
	text := `
config firewall wildcard-fqdn custom
    edit "adobe"
        set wildcard-fqdn "*.adobe.com"
    next
    edit "orphan-wfqdn"
        set wildcard-fqdn "*.orphan.test"
    next
end
config firewall policy
    edit 1
        set name "WFQDN-Test"
        set srcintf "port1"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "adobe"
        set action accept
        set schedule "always"
        set service "ALL"
        set logtraffic all
    next
end
`
	p := NewFortiGateParser(text)
	c := NewVersaConverter(p, newTestConfig())
	out := c.Convert()

	if !strings.Contains(out, "addresses address adobe fqdn *.adobe.com") {
		t.Error("missing wildcard-fqdn address object")
	}
	if !strings.Contains(out, "match destination address address-list [ adobe ]") {
		t.Error("missing wildcard-fqdn in destination match")
	}
	// orphan should be skipped
	if strings.Contains(out, "orphan-wfqdn") {
		t.Error("orphan wildcard-fqdn should be skipped")
	}
	// Check DNS proxy warning
	report := c.Report.Render()
	if !strings.Contains(report, "Wildcard FQDN objects require DNS Proxy enabled on VOS") {
		t.Error("missing DNS proxy warning")
	}
}

func TestConvertWildcardFQDNOrphan(t *testing.T) {
	text := `
config firewall wildcard-fqdn custom
    edit "orphan-only"
        set wildcard-fqdn "*.orphan.test"
    next
end
config firewall policy
    edit 1
        set name "No-WFQDN"
        set srcintf "port1"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
        set logtraffic all
    next
end
`
	p := NewFortiGateParser(text)
	c := NewVersaConverter(p, newTestConfig())
	out := c.Convert()

	if strings.Contains(out, "orphan-only") {
		t.Error("orphan wildcard-fqdn should not appear in output")
	}
	report := c.Report.Render()
	if !strings.Contains(report, "wildcard-fqdn \"orphan-only\" (orphan)") {
		t.Error("missing orphan skip report")
	}
}

func TestConvertDecryptionWithExemptions(t *testing.T) {
	text := `
config firewall ssl-ssh-profile
    edit "deep-inspection"
        set ssl-exempt-categories 72 7
    next
end
config firewall policy
    edit 1
        set name "Exempt-Test"
        set srcintf "port1"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
        set logtraffic all
        set ssl-ssh-profile "deep-inspection"
    next
end
`
	p := NewFortiGateParser(text)
	c := NewVersaConverter(p, newTestConfig())
	out := c.Convert()

	// Should have no-decrypt rule BEFORE decrypt rule
	noDecryptIdx := strings.Index(out, "nodecrypt-Exempt-Test")
	decryptIdx := strings.Index(out, "decrypt-Exempt-Test")
	if noDecryptIdx < 0 {
		t.Error("missing nodecrypt rule")
	}
	if decryptIdx < 0 {
		t.Error("missing decrypt rule")
	}
	if noDecryptIdx > decryptIdx {
		t.Error("nodecrypt rule should come before decrypt rule")
	}
	if !strings.Contains(out, "match url-category predefined [ peer_to_peer abortion ]") {
		t.Error("missing url-category match in nodecrypt rule")
	}
	if !strings.Contains(out, "nodecrypt-Exempt-Test") && !strings.Contains(out, "set action allow") {
		t.Error("missing allow action on nodecrypt rule")
	}
}

func TestConvertDecryptionFQDNExemption(t *testing.T) {
	text := `
config firewall wildcard-fqdn custom
    edit "adobe"
        set wildcard-fqdn "*.adobe.com"
    next
end
config firewall ssl-ssh-profile
    edit "SSL_Inspection"
        config ssl-exempt
            edit 1
                set type wildcard-fqdn
                set wildcard-fqdn "adobe"
            next
        end
    next
end
config firewall policy
    edit 1
        set name "FQDN-Exempt"
        set srcintf "port1"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
        set logtraffic all
        set ssl-ssh-profile "SSL_Inspection"
    next
end
`
	p := NewFortiGateParser(text)
	c := NewVersaConverter(p, newTestConfig())
	out := c.Convert()

	if !strings.Contains(out, "addresses address adobe fqdn *.adobe.com") {
		t.Error("missing wildcard-fqdn address object for FQDN exemption")
	}
	if !strings.Contains(out, "nodecrypt-FQDN-Exempt") {
		t.Error("missing nodecrypt rule for FQDN exemption")
	}
	if !strings.Contains(out, "match destination address address-list [ adobe ]") {
		t.Error("missing FQDN destination match in nodecrypt rule")
	}
}

func TestConvertURLFilterBlacklist(t *testing.T) {
	text := `
config webfilter urlfilter
    edit 1
        set name "Test_URLs"
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
            edit 4
                set url "(xxx|porn)"
                set type regex
                set action block
            next
            edit 5
                set url "*youtube.com"
                set type wildcard
                set action monitor
            next
        end
    next
end
config webfilter profile
    edit "test-wf"
        config web
            set urlfilter-table 1
        end
        config ftgd-wf
            config filters
                edit 1
                    set category 2
                    set action block
                next
            end
        end
    next
end
config firewall policy
    edit 1
        set name "URL-Filter-Test"
        set srcintf "port1"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
        set logtraffic all
        set webfilter-profile "test-wf"
    next
end
`
	p := NewFortiGateParser(text)
	cfg := newTestConfig()
	c := NewVersaConverter(p, cfg)
	out := c.Convert()

	// Should have blacklist patterns (note: %q formatting double-escapes backslashes)
	if !strings.Contains(out, `blacklist patterns [ ".*facebook\\.com" ".*gambling\\.com" "(xxx|porn)" ]`) {
		t.Errorf("missing or incorrect blacklist patterns in output")
	}
	// youtube is monitor, should NOT be in blacklist
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "blacklist patterns") && strings.Contains(line, "youtube") {
			t.Errorf("monitor entry youtube should not be in blacklist patterns")
		}
	}
	// Bug 1: Monitor patterns merged into main profile whitelist
	if !strings.Contains(out, `whitelist patterns [ ".*\\.safe-site\\.com" ".*youtube\\.com" ]`) {
		t.Errorf("missing merged whitelist patterns (exempt + monitor) in output")
	}
	// Should still have category block
	if !strings.Contains(out, "religion") {
		t.Error("missing category-action-map block")
	}
	// Bug 1: Whitelist log-enable true (because monitor patterns exist)
	if !strings.Contains(out, "whitelist log-enable true") {
		t.Error("missing whitelist log-enable true in main profile")
	}
	// Bug 1: No separate _url_monitor profile
	if strings.Contains(out, "_url_monitor") {
		t.Error("_url_monitor profile should not exist — monitor patterns merged into main profile")
	}
	// Bug 1: No separate monitor-* access-policy rule
	if strings.Contains(out, "monitor-URL-Filter-Test") {
		t.Error("monitor-URL-Filter-Test rule should not exist — monitor patterns merged into main profile")
	}
	if !strings.Contains(out, "set lef event both") {
		t.Error("missing LEF logging")
	}
}

func TestFortiURLToVersaRegex(t *testing.T) {
	tests := []struct {
		url, typ, want string
	}{
		{"*facebook.com", "wildcard", `.*facebook\.com`},
		{"*.corp.example.com", "wildcard", `.*\.corp\.example\.com`},
		{"gambling.com", "simple", `.*gambling\.com`},
		{"(xxx|porn)", "regex", "(xxx|porn)"},
	}
	for _, tt := range tests {
		got := fortiURLToVersaRegex(tt.url, tt.typ)
		if got != tt.want {
			t.Errorf("fortiURLToVersaRegex(%q, %q) = %q, want %q", tt.url, tt.typ, got, tt.want)
		}
	}
}

func TestConvertOnetimeSchedule(t *testing.T) {
	text := `
config firewall schedule onetime
    edit "Physical Inventory Schedule"
        set start 00:01 2019/10/11
        set end 23:59 2019/10/28
    next
end
config firewall policy
    edit 1
        set name "Inventory-Check"
        set srcintf "port1"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "Physical Inventory Schedule"
        set service "ALL"
        set logtraffic all
    next
end
`
	p := NewFortiGateParser(text)
	c := NewVersaConverter(p, newTestConfig())
	out := c.Convert()

	if !strings.Contains(out, "non-recurring 2019/10/11@00:01-2019/10/28@23:59") {
		t.Errorf("missing onetime schedule, got: %s", out)
	}
	if !strings.Contains(out, "match schedule Physical_Inventory_Schedule") {
		t.Error("missing schedule reference in policy")
	}
}

func TestConvertTrafficShaperWarning(t *testing.T) {
	text := `
config firewall policy
    edit 1
        set name "Shaper-Test"
        set srcintf "port1"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
        set logtraffic all
        set traffic-shaper "high-priority"
    next
end
`
	p := NewFortiGateParser(text)
	c := NewVersaConverter(p, newTestConfig())
	c.Convert()
	report := c.Report.Render()

	if !strings.Contains(report, `traffic-shaper "high-priority"`) {
		t.Error("missing traffic-shaper warning")
	}
	if !strings.Contains(report, "Versa QoS uses Class of Service") {
		t.Error("missing QoS warning text")
	}
}

func TestConvertAppBlockRule(t *testing.T) {
	text := `
config application list
    edit "Block_P2P"
        config entries
            edit 1
                set category 8
                set action block
            next
            edit 2
                set application 16354
                set action block
            next
        end
    next
end
config firewall policy
    edit 1
        set name "App-Block-Test"
        set srcintf "port1"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
        set logtraffic all
        set application-list "Block_P2P"
    next
end
`
	p := NewFortiGateParser(text)
	c := NewVersaConverter(p, newTestConfig())
	out := c.Convert()

	// Bug 2: Should have appblock deny pre-rule
	if !strings.Contains(out, "appblock-App-Block-Test") {
		t.Error("missing appblock deny pre-rule")
	}
	if !strings.Contains(out, "appblock-App-Block-Test set action deny") {
		t.Error("appblock rule should have deny action")
	}
	if !strings.Contains(out, "appblock-App-Block-Test set set-type public") {
		t.Error("appblock rule should have set-type public")
	}
	// appblock should have app matching
	found := false
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "appblock-App-Block-Test") && strings.Contains(line, "match application") {
			found = true
			break
		}
	}
	if !found {
		t.Error("appblock rule should have match application")
	}
	// Main rule should NOT have match application
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "access-policy App-Block-Test") && !strings.Contains(line, "appblock-") && strings.Contains(line, "match application") {
			t.Error("main allow rule should NOT have match application")
		}
	}
	// appblock rule should come BEFORE main rule
	appblockIdx := strings.Index(out, "appblock-App-Block-Test")
	mainIdx := strings.Index(out, "access-policy App-Block-Test rule-disable")
	if appblockIdx > mainIdx {
		t.Error("appblock rule should come before main rule")
	}
}

func TestConvertDNSFilterMerge(t *testing.T) {
	text := `
config dnsfilter profile
    edit "DNS_Block"
        config ftgd-dns
            config filters
                edit 1
                    set category 26
                    set action block
                next
                edit 2
                    set category 72
                    set action block
                next
            end
        end
    next
end
config webfilter profile
    edit "WF_Test"
        config ftgd-wf
            config filters
                edit 1
                    set category 2
                    set action block
                next
            end
        end
    next
end
config firewall policy
    edit 1
        set name "DNS-Merge-Test"
        set srcintf "port1"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
        set logtraffic all
        set webfilter-profile "WF_Test"
        set dnsfilter-profile "DNS_Block"
    next
end
`
	p := NewFortiGateParser(text)
	c := NewVersaConverter(p, newTestConfig())
	out := c.Convert()

	// Bug 3: No dns-filtering line in output
	if strings.Contains(out, "dns-filtering") {
		t.Error("should not have dns-filtering lines — merged into URL filtering")
	}
	// Should have URL filtering profile with DNS categories merged
	if !strings.Contains(out, "url-filtering-profile WF_Test") {
		t.Error("missing URL filtering profile")
	}
	// DNS cat 26 = malware_sites, cat 72 = peer_to_peer should be in block categories
	if !strings.Contains(out, "malware_sites") {
		t.Error("missing malware_sites from DNS filter merge")
	}
	if !strings.Contains(out, "peer_to_peer") {
		t.Error("missing peer_to_peer from DNS filter merge")
	}
	// Check report mentions DNS merge
	report := c.Report.Render()
	if !strings.Contains(report, "DNS filter categories merged") {
		t.Error("missing DNS merge report info")
	}
}

func TestConvertDNSFilterOnly(t *testing.T) {
	text := `
config dnsfilter profile
    edit "DNS_Only"
        config ftgd-dns
            config filters
                edit 1
                    set category 26
                    set action block
                next
            end
        end
    next
end
config firewall policy
    edit 1
        set name "DNS-Only-Test"
        set srcintf "port1"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
        set logtraffic all
        set dnsfilter-profile "DNS_Only"
    next
end
`
	p := NewFortiGateParser(text)
	c := NewVersaConverter(p, newTestConfig())
	out := c.Convert()

	// Bug 3: Should create URL filtering profile from DNS filter categories
	if !strings.Contains(out, "url-filtering-profile DNS_Only") {
		t.Error("missing URL filtering profile from DNS-only policy")
	}
	if !strings.Contains(out, "malware_sites") {
		t.Error("missing malware_sites in DNS-only URL filtering profile")
	}
	// Should attach the profile in the rule
	if !strings.Contains(out, "url-filtering user-defined DNS_Only") {
		t.Error("missing url-filtering user-defined in rule for DNS-only policy")
	}
}

func TestConvertDecryptionWithProtocols(t *testing.T) {
	text := `
config firewall ssl-ssh-profile
    edit "deep-inspection"
        config https
            set ports 443
            set status deep-inspection
        end
        config ftps
            set ports 990
            set status deep-inspection
        end
        config imaps
            set ports 993
            set status deep-inspection
        end
    next
end
config firewall policy
    edit 1
        set name "Multi-Proto-Decrypt"
        set srcintf "port1"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
        set logtraffic all
        set ssl-ssh-profile "deep-inspection"
    next
end
`
	p := NewFortiGateParser(text)
	c := NewVersaConverter(p, newTestConfig())
	out := c.Convert()

	// Bug 4: Decrypt rule should have all 3 protocols
	if !strings.Contains(out, "predefined-services-list [ https ftps imaps ]") {
		t.Errorf("decrypt rule should have https ftps imaps services, got output:\n%s", out)
	}
}

func TestConvertDecryptionCertInspectionExcluded(t *testing.T) {
	text := `
config firewall ssl-ssh-profile
    edit "deep-inspection"
        config https
            set ports 443
            set status deep-inspection
        end
        config ftps
            set ports 990
            set status certificate-inspection
        end
    next
end
config firewall policy
    edit 1
        set name "Cert-Only-Test"
        set srcintf "port1"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
        set logtraffic all
        set ssl-ssh-profile "deep-inspection"
    next
end
`
	p := NewFortiGateParser(text)
	c := NewVersaConverter(p, newTestConfig())
	out := c.Convert()

	// Bug 4: Only deep-inspection protocols should appear
	if !strings.Contains(out, "predefined-services-list [ https ]") {
		t.Errorf("decrypt rule should only have https (ftps is cert-inspection), got output:\n%s", out)
	}
	// ftps should NOT be in services (it's only certificate-inspection)
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "decrypt-Cert-Only-Test") && strings.Contains(line, "predefined-services-list") && strings.Contains(line, "ftps") {
			t.Error("ftps should not be in decrypt services (certificate-inspection only)")
		}
	}
}
