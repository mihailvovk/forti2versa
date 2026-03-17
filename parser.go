package forti2versa

import (
	"strconv"
	"strings"
)

// FortiGateParser parses FortiGate config text into typed Go structs.
type FortiGateParser struct {
	Addresses   map[string]*AddressObj
	AddrOrder   []string // insertion-order keys for Addresses
	AddrGroups  map[string]*AddrGroup
	AGrpOrder   []string
	Services    map[string]*ServiceObj
	SvcOrder    []string
	SvcGroups   map[string]*SvcGroup
	SGrpOrder   []string
	Policies    []*PolicyObj
	WebfilterProfiles map[string]*WebfilterProfile
	AppListProfiles   map[string]*AppListProfile
	WildcardFQDNs     map[string]*WildcardFQDN
	WFQDNOrder        []string
	SSLSSHProfiles    map[string]*SSLSSHProfile
	URLFilters        map[int]*URLFilterTable
	OnetimeSchedules  map[string]*OnetimeSchedule
}

func NewFortiGateParser(text string) *FortiGateParser {
	p := &FortiGateParser{
		Addresses:         make(map[string]*AddressObj),
		AddrGroups:        make(map[string]*AddrGroup),
		Services:          make(map[string]*ServiceObj),
		SvcGroups:         make(map[string]*SvcGroup),
		WebfilterProfiles: make(map[string]*WebfilterProfile),
		AppListProfiles:   make(map[string]*AppListProfile),
		WildcardFQDNs:     make(map[string]*WildcardFQDN),
		SSLSSHProfiles:    make(map[string]*SSLSSHProfile),
		URLFilters:        make(map[int]*URLFilterTable),
		OnetimeSchedules:  make(map[string]*OnetimeSchedule),
	}
	p.parse(text)
	return p
}

// preprocess joins backslash continuations.
func preprocess(text string) []string {
	var lines []string
	var buf strings.Builder
	for _, raw := range strings.Split(text, "\n") {
		stripped := strings.TrimRight(raw, " \t\r")
		if strings.HasSuffix(stripped, `\`) {
			buf.WriteString(strings.TrimRight(stripped[:len(stripped)-1], " \t"))
			buf.WriteByte(' ')
			continue
		}
		buf.WriteString(stripped)
		lines = append(lines, buf.String())
		buf.Reset()
	}
	if buf.Len() > 0 {
		lines = append(lines, buf.String())
	}
	return lines
}

// parseQuotedValues parses: "A" "B" "C" or unquoted tokens.
func parseQuotedValues(rest string) []string {
	var values []string
	i := 0
	for i < len(rest) {
		if rest[i] == '"' {
			j := i + 1
			for j < len(rest) && rest[j] != '"' {
				j++
			}
			values = append(values, rest[i+1:j])
			if j < len(rest) {
				j++ // skip closing quote
			}
			i = j
		} else if rest[i] == ' ' || rest[i] == '\t' {
			i++
		} else {
			j := i
			for j < len(rest) && rest[j] != ' ' && rest[j] != '\t' && rest[j] != '"' {
				j++
			}
			values = append(values, rest[i:j])
			i = j
		}
	}
	return values
}

func skipComment(line string) string {
	s := strings.TrimSpace(line)
	if strings.HasPrefix(s, "#") {
		return ""
	}
	return s
}

func (p *FortiGateParser) parse(text string) {
	lines := preprocess(text)
	i := 0
	for i < len(lines) {
		line := strings.TrimSpace(lines[i])
		switch {
		case line == "config firewall address":
			i = p.parseAddressBlock(lines, i+1)
		case line == "config firewall addrgrp":
			i = p.parseAddrGrpBlock(lines, i+1)
		case line == "config firewall service custom":
			i = p.parseServiceBlock(lines, i+1)
		case line == "config firewall service group":
			i = p.parseSvcGroupBlock(lines, i+1)
		case line == "config webfilter profile":
			i = p.parseWebfilterProfileBlock(lines, i+1)
		case line == "config application list":
			i = p.parseAppListBlock(lines, i+1)
		case line == "config firewall wildcard-fqdn custom":
			i = p.parseWildcardFQDNBlock(lines, i+1)
		case line == "config firewall ssl-ssh-profile":
			i = p.parseSSLSSHProfileBlock(lines, i+1)
		case line == "config webfilter urlfilter":
			i = p.parseURLFilterBlock(lines, i+1)
		case line == "config firewall schedule onetime":
			i = p.parseOnetimeScheduleBlock(lines, i+1)
		case line == "config firewall policy":
			i = p.parsePolicyBlock(lines, i+1)
		default:
			i++
		}
	}
}

func (p *FortiGateParser) saveAddr(obj *AddressObj) {
	if obj == nil {
		return
	}
	if _, exists := p.Addresses[obj.Name]; !exists {
		p.AddrOrder = append(p.AddrOrder, obj.Name)
	}
	p.Addresses[obj.Name] = obj
}

func (p *FortiGateParser) parseAddressBlock(lines []string, start int) int {
	i := start
	depth := 1
	var obj *AddressObj
	for i < len(lines) && depth > 0 {
		s := skipComment(lines[i])
		if s == "" {
			i++
			continue
		}
		if s == "end" {
			depth--
			if depth == 0 {
				p.saveAddr(obj)
				return i + 1
			}
			i++
			continue
		}
		if strings.HasPrefix(s, "config ") {
			depth++
			i++
			continue
		}
		if strings.HasPrefix(s, "edit ") {
			p.saveAddr(obj)
			name := parseQuotedValues(s[5:])[0]
			obj = &AddressObj{Name: name, Type: "ipmask"}
			i++
			continue
		}
		if s == "next" {
			p.saveAddr(obj)
			obj = nil
			i++
			continue
		}
		if strings.HasPrefix(s, "set ") && obj != nil {
			applyAddressSet(obj, s)
		}
		i++
	}
	return i
}

func applyAddressSet(obj *AddressObj, line string) {
	parts := splitN(line, 3)
	if len(parts) < 3 {
		return
	}
	key := parts[1]
	rest := parts[2]
	vals := parseQuotedValues(rest)
	switch key {
	case "type":
		obj.Type = vals[0]
	case "subnet":
		obj.Subnet = strings.Join(vals, " ")
	case "fqdn":
		obj.FQDN = vals[0]
	case "start-ip":
		obj.StartIP = vals[0]
	case "end-ip":
		obj.EndIP = vals[0]
	case "country":
		obj.Country = vals[0]
	case "comment":
		if len(vals) > 0 {
			obj.Comment = vals[0]
		}
	}
}

func (p *FortiGateParser) saveAddrGrp(obj *AddrGroup) {
	if obj == nil {
		return
	}
	if _, exists := p.AddrGroups[obj.Name]; !exists {
		p.AGrpOrder = append(p.AGrpOrder, obj.Name)
	}
	p.AddrGroups[obj.Name] = obj
}

func (p *FortiGateParser) parseAddrGrpBlock(lines []string, start int) int {
	i := start
	depth := 1
	var obj *AddrGroup
	for i < len(lines) && depth > 0 {
		s := skipComment(lines[i])
		if s == "" {
			i++
			continue
		}
		if s == "end" {
			depth--
			if depth == 0 {
				p.saveAddrGrp(obj)
				return i + 1
			}
			i++
			continue
		}
		if strings.HasPrefix(s, "config ") {
			depth++
			i++
			continue
		}
		if strings.HasPrefix(s, "edit ") {
			p.saveAddrGrp(obj)
			name := parseQuotedValues(s[5:])[0]
			obj = &AddrGroup{Name: name}
			i++
			continue
		}
		if s == "next" {
			p.saveAddrGrp(obj)
			obj = nil
			i++
			continue
		}
		if strings.HasPrefix(s, "set ") && obj != nil {
			parts := splitN(s, 3)
			if len(parts) >= 3 {
				key, rest := parts[1], parts[2]
				vals := parseQuotedValues(rest)
				switch key {
				case "member":
					obj.Members = vals
				case "comment":
					if len(vals) > 0 {
						obj.Comment = vals[0]
					}
				}
			}
		}
		i++
	}
	return i
}

func (p *FortiGateParser) saveSvc(obj *ServiceObj) {
	if obj == nil {
		return
	}
	if _, exists := p.Services[obj.Name]; !exists {
		p.SvcOrder = append(p.SvcOrder, obj.Name)
	}
	p.Services[obj.Name] = obj
}

func (p *FortiGateParser) parseServiceBlock(lines []string, start int) int {
	i := start
	depth := 1
	var obj *ServiceObj
	for i < len(lines) && depth > 0 {
		s := skipComment(lines[i])
		if s == "" {
			i++
			continue
		}
		if s == "end" {
			depth--
			if depth == 0 {
				p.saveSvc(obj)
				return i + 1
			}
			i++
			continue
		}
		if strings.HasPrefix(s, "config ") {
			depth++
			i++
			continue
		}
		if strings.HasPrefix(s, "edit ") {
			p.saveSvc(obj)
			name := parseQuotedValues(s[5:])[0]
			obj = &ServiceObj{Name: name}
			i++
			continue
		}
		if s == "next" {
			p.saveSvc(obj)
			obj = nil
			i++
			continue
		}
		if strings.HasPrefix(s, "set ") && obj != nil {
			parts := splitN(s, 3)
			if len(parts) >= 3 {
				key, rest := parts[1], parts[2]
				vals := parseQuotedValues(rest)
				switch key {
				case "protocol":
					obj.Protocol = strings.Join(vals, " ")
				case "tcp-portrange":
					obj.TCPPortRange = strings.Join(vals, " ")
				case "udp-portrange":
					obj.UDPPortRange = strings.Join(vals, " ")
				case "comment":
					if len(vals) > 0 {
						obj.Comment = vals[0]
					}
				}
			}
		}
		i++
	}
	return i
}

func (p *FortiGateParser) saveSvcGrp(obj *SvcGroup) {
	if obj == nil {
		return
	}
	if _, exists := p.SvcGroups[obj.Name]; !exists {
		p.SGrpOrder = append(p.SGrpOrder, obj.Name)
	}
	p.SvcGroups[obj.Name] = obj
}

func (p *FortiGateParser) parseSvcGroupBlock(lines []string, start int) int {
	i := start
	depth := 1
	var obj *SvcGroup
	for i < len(lines) && depth > 0 {
		s := skipComment(lines[i])
		if s == "" {
			i++
			continue
		}
		if s == "end" {
			depth--
			if depth == 0 {
				p.saveSvcGrp(obj)
				return i + 1
			}
			i++
			continue
		}
		if strings.HasPrefix(s, "config ") {
			depth++
			i++
			continue
		}
		if strings.HasPrefix(s, "edit ") {
			p.saveSvcGrp(obj)
			name := parseQuotedValues(s[5:])[0]
			obj = &SvcGroup{Name: name}
			i++
			continue
		}
		if s == "next" {
			p.saveSvcGrp(obj)
			obj = nil
			i++
			continue
		}
		if strings.HasPrefix(s, "set ") && obj != nil {
			parts := splitN(s, 3)
			if len(parts) >= 3 {
				key, rest := parts[1], parts[2]
				vals := parseQuotedValues(rest)
				switch key {
				case "member":
					obj.Members = vals
				case "comment":
					if len(vals) > 0 {
						obj.Comment = vals[0]
					}
				}
			}
		}
		i++
	}
	return i
}

func (p *FortiGateParser) parseWebfilterProfileBlock(lines []string, start int) int {
	i := start
	depth := 1
	var obj *WebfilterProfile
	inFtgdFilters := false
	var catObj *WebfilterCategory
	for i < len(lines) && depth > 0 {
		s := skipComment(lines[i])
		if s == "" {
			i++
			continue
		}
		if s == "end" {
			if catObj != nil && obj != nil {
				obj.Categories = append(obj.Categories, *catObj)
				catObj = nil
			}
			depth--
			if depth == 2 {
				inFtgdFilters = false
			}
			if depth == 0 {
				if obj != nil {
					p.WebfilterProfiles[obj.Name] = obj
				}
				return i + 1
			}
			i++
			continue
		}
		if strings.HasPrefix(s, "config ") {
			depth++
			if strings.Contains(s, "filters") && depth >= 3 {
				inFtgdFilters = true
			}
			i++
			continue
		}
		if strings.HasPrefix(s, "edit ") && depth == 1 {
			if obj != nil {
				p.WebfilterProfiles[obj.Name] = obj
			}
			name := parseQuotedValues(s[5:])[0]
			obj = &WebfilterProfile{Name: name}
			i++
			continue
		}
		if strings.HasPrefix(s, "edit ") && inFtgdFilters {
			if catObj != nil && obj != nil {
				obj.Categories = append(obj.Categories, *catObj)
			}
			idStr := parseQuotedValues(s[5:])[0]
			id, _ := strconv.Atoi(idStr)
			catObj = &WebfilterCategory{ID: id}
			i++
			continue
		}
		if s == "next" {
			if inFtgdFilters && catObj != nil && obj != nil {
				obj.Categories = append(obj.Categories, *catObj)
				catObj = nil
			} else if !inFtgdFilters && depth == 1 {
				if obj != nil {
					p.WebfilterProfiles[obj.Name] = obj
					obj = nil
				}
			}
			i++
			continue
		}
		if strings.HasPrefix(s, "set ") && obj != nil {
			parts := splitN(s, 3)
			if len(parts) >= 3 {
				key, rest := parts[1], parts[2]
				vals := parseQuotedValues(rest)
				switch key {
				case "comment":
					if len(vals) > 0 {
						obj.Comment = vals[0]
					}
				case "urlfilter-table":
					obj.URLFilterTable, _ = strconv.Atoi(vals[0])
				case "category":
					if catObj != nil {
						catObj.ID, _ = strconv.Atoi(vals[0])
					}
				case "action":
					if catObj != nil {
						catObj.Action = vals[0]
					}
				}
			}
		}
		i++
	}
	return i
}

func (p *FortiGateParser) parseAppListBlock(lines []string, start int) int {
	i := start
	depth := 1
	var obj *AppListProfile
	inEntries := false
	var entry *AppListEntry
	for i < len(lines) && depth > 0 {
		s := skipComment(lines[i])
		if s == "" {
			i++
			continue
		}
		if s == "end" {
			if entry != nil && obj != nil {
				obj.Entries = append(obj.Entries, *entry)
				entry = nil
			}
			depth--
			if depth == 1 {
				inEntries = false
			}
			if depth == 0 {
				if obj != nil {
					p.AppListProfiles[obj.Name] = obj
				}
				return i + 1
			}
			i++
			continue
		}
		if strings.HasPrefix(s, "config ") {
			depth++
			if strings.Contains(s, "entries") {
				inEntries = true
			}
			i++
			continue
		}
		if strings.HasPrefix(s, "edit ") && depth == 1 {
			if obj != nil {
				p.AppListProfiles[obj.Name] = obj
			}
			name := parseQuotedValues(s[5:])[0]
			obj = &AppListProfile{Name: name}
			i++
			continue
		}
		if strings.HasPrefix(s, "edit ") && inEntries {
			if entry != nil && obj != nil {
				obj.Entries = append(obj.Entries, *entry)
			}
			entry = &AppListEntry{}
			i++
			continue
		}
		if s == "next" {
			if inEntries && entry != nil && obj != nil {
				obj.Entries = append(obj.Entries, *entry)
				entry = nil
			} else if !inEntries && depth == 1 {
				if obj != nil {
					p.AppListProfiles[obj.Name] = obj
					obj = nil
				}
			}
			i++
			continue
		}
		if strings.HasPrefix(s, "set ") {
			parts := splitN(s, 3)
			if len(parts) >= 3 {
				key, rest := parts[1], parts[2]
				vals := parseQuotedValues(rest)
				switch {
				case key == "comment" && obj != nil:
					obj.Comment = vals[0]
				case key == "unknown-application-action" && obj != nil:
					obj.UnknownApplicationAction = vals[0]
				case key == "category" && entry != nil:
					for _, v := range vals {
						id, _ := strconv.Atoi(v)
						entry.Category = append(entry.Category, id)
					}
				case key == "application" && entry != nil:
					entry.Application, _ = strconv.Atoi(vals[0])
				case key == "action" && entry != nil:
					entry.Action = vals[0]
				}
			}
		}
		i++
	}
	return i
}

func (p *FortiGateParser) parsePolicyBlock(lines []string, start int) int {
	i := start
	depth := 1
	var obj *PolicyObj
	inMultilineComment := false
	var commentBuf strings.Builder
	for i < len(lines) && depth > 0 {
		raw := lines[i]
		// Handle multiline quoted comments
		if inMultilineComment {
			if idx := strings.Index(raw, `"`); idx >= 0 {
				commentBuf.WriteByte(' ')
				commentBuf.WriteString(strings.TrimSpace(raw[:idx]))
				if obj != nil {
					obj.Comments = strings.TrimSpace(commentBuf.String())
				}
				inMultilineComment = false
				commentBuf.Reset()
				i++
				continue
			}
			commentBuf.WriteByte(' ')
			commentBuf.WriteString(strings.TrimSpace(raw))
			i++
			continue
		}

		s := skipComment(raw)
		if s == "" {
			i++
			continue
		}
		if s == "end" {
			depth--
			if depth == 0 {
				if obj != nil {
					p.Policies = append(p.Policies, obj)
				}
				return i + 1
			}
			i++
			continue
		}
		if strings.HasPrefix(s, "config ") {
			depth++
			i++
			continue
		}
		if strings.HasPrefix(s, "edit ") {
			if obj != nil {
				p.Policies = append(p.Policies, obj)
			}
			vals := parseQuotedValues(s[5:])
			id, _ := strconv.Atoi(vals[0])
			obj = &PolicyObj{ID: id, Action: "accept"}
			i++
			continue
		}
		if s == "next" {
			if obj != nil {
				p.Policies = append(p.Policies, obj)
				obj = nil
			}
			i++
			continue
		}
		if strings.HasPrefix(s, "set ") && obj != nil {
			applyPolicySet(obj, s)
			// Check for unclosed multiline comment
			if strings.HasPrefix(s, "set comments ") {
				rest := s[len("set comments "):]
				if strings.HasPrefix(rest, `"`) && strings.Count(rest, `"`) == 1 {
					inMultilineComment = true
					commentBuf.Reset()
					commentBuf.WriteString(rest[1:])
				}
			}
		}
		i++
	}
	if obj != nil {
		p.Policies = append(p.Policies, obj)
	}
	return i
}

func applyPolicySet(obj *PolicyObj, line string) {
	// Strip invisible chars from key portion
	clean := reInvisible.ReplaceAllString(line, "")
	parts := splitN(clean, 3)
	if len(parts) < 3 {
		key := ""
		if len(parts) > 1 {
			key = parts[1]
		}
		if key == "nat" {
			obj.NAT = "enable"
		}
		return
	}
	key := parts[1]
	rest := parts[2]
	vals := parseQuotedValues(rest)
	switch key {
	case "name":
		obj.Name = vals[0]
	case "srcintf":
		obj.SrcIntf = vals[0]
	case "dstintf":
		obj.DstIntf = vals[0]
	case "srcaddr":
		obj.SrcAddr = vals
	case "dstaddr":
		obj.DstAddr = vals
	case "action":
		obj.Action = vals[0]
	case "schedule":
		obj.Schedule = vals[0]
	case "service":
		obj.Service = vals
	case "groups":
		obj.Groups = vals
	case "users":
		obj.Users = vals
	case "logtraffic":
		obj.LogTraffic = vals[0]
	case "nat":
		obj.NAT = vals[0]
	case "comments":
		// May be multiline - handled in caller for unclosed quotes
		if strings.HasPrefix(rest, `"`) && strings.HasSuffix(rest, `"`) && strings.Count(rest, `"`) >= 2 {
			obj.Comments = vals[0]
		} else if !strings.HasPrefix(rest, `"`) {
			obj.Comments = vals[0]
		}
	case "utm-status":
		obj.UTMStatus = vals[0]
	case "webfilter-profile":
		obj.WebfilterProfile = vals[0]
	case "av-profile":
		obj.AVProfile = vals[0]
	case "ips-sensor":
		obj.IPSSensor = vals[0]
	case "application-list":
		obj.ApplicationList = vals[0]
	case "dnsfilter-profile":
		obj.DNSFilterProfile = vals[0]
	case "ssl-ssh-profile":
		obj.SSLSSHProfile = vals[0]
	case "traffic-shaper":
		obj.TrafficShaper = vals[0]
	}
}

// splitN splits on whitespace up to n fields (like Python's str.split(None, n-1)).
func splitN(s string, n int) []string {
	var result []string
	i := 0
	for len(result) < n-1 {
		// skip whitespace
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		if i >= len(s) {
			break
		}
		j := i
		for j < len(s) && s[j] != ' ' && s[j] != '\t' {
			j++
		}
		result = append(result, s[i:j])
		i = j
	}
	// remaining
	if i < len(s) {
		// skip whitespace before remainder
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		if i < len(s) {
			result = append(result, s[i:])
		}
	}
	return result
}

// --- Wildcard FQDN ---

func (p *FortiGateParser) parseWildcardFQDNBlock(lines []string, start int) int {
	i := start
	depth := 1
	var obj *WildcardFQDN
	for i < len(lines) && depth > 0 {
		s := skipComment(lines[i])
		if s == "" {
			i++
			continue
		}
		if s == "end" {
			depth--
			if depth == 0 {
				p.saveWFQDN(obj)
				return i + 1
			}
			i++
			continue
		}
		if strings.HasPrefix(s, "config ") {
			depth++
			i++
			continue
		}
		if strings.HasPrefix(s, "edit ") {
			p.saveWFQDN(obj)
			name := parseQuotedValues(s[5:])[0]
			obj = &WildcardFQDN{Name: name}
			i++
			continue
		}
		if s == "next" {
			p.saveWFQDN(obj)
			obj = nil
			i++
			continue
		}
		if strings.HasPrefix(s, "set ") && obj != nil {
			parts := splitN(s, 3)
			if len(parts) >= 3 {
				key := parts[1]
				vals := parseQuotedValues(parts[2])
				if key == "wildcard-fqdn" && len(vals) > 0 {
					obj.WildcardFQDN = vals[0]
				}
			}
		}
		i++
	}
	return i
}

func (p *FortiGateParser) saveWFQDN(obj *WildcardFQDN) {
	if obj == nil {
		return
	}
	if _, exists := p.WildcardFQDNs[obj.Name]; !exists {
		p.WFQDNOrder = append(p.WFQDNOrder, obj.Name)
	}
	p.WildcardFQDNs[obj.Name] = obj
}

// --- SSL/SSH Profiles ---

func (p *FortiGateParser) parseSSLSSHProfileBlock(lines []string, start int) int {
	i := start
	depth := 1
	var obj *SSLSSHProfile
	inSSLExempt := false
	var exemption *SSLExemption
	for i < len(lines) && depth > 0 {
		s := skipComment(lines[i])
		if s == "" {
			i++
			continue
		}
		if s == "end" {
			if exemption != nil && obj != nil {
				obj.Exemptions = append(obj.Exemptions, *exemption)
				exemption = nil
			}
			depth--
			if depth == 1 {
				inSSLExempt = false
			}
			if depth == 0 {
				if obj != nil {
					p.SSLSSHProfiles[obj.Name] = obj
				}
				return i + 1
			}
			i++
			continue
		}
		if strings.HasPrefix(s, "config ") {
			depth++
			if strings.Contains(s, "ssl-exempt") {
				inSSLExempt = true
			}
			i++
			continue
		}
		if strings.HasPrefix(s, "edit ") && depth == 1 {
			if obj != nil {
				p.SSLSSHProfiles[obj.Name] = obj
			}
			name := parseQuotedValues(s[5:])[0]
			obj = &SSLSSHProfile{Name: name}
			i++
			continue
		}
		if strings.HasPrefix(s, "edit ") && inSSLExempt {
			if exemption != nil && obj != nil {
				obj.Exemptions = append(obj.Exemptions, *exemption)
			}
			exemption = &SSLExemption{Type: "fortiguard-cat"}
			i++
			continue
		}
		if s == "next" {
			if inSSLExempt && exemption != nil && obj != nil {
				obj.Exemptions = append(obj.Exemptions, *exemption)
				exemption = nil
			} else if !inSSLExempt && depth == 1 {
				if obj != nil {
					p.SSLSSHProfiles[obj.Name] = obj
					obj = nil
				}
			}
			i++
			continue
		}
		if strings.HasPrefix(s, "set ") {
			parts := splitN(s, 3)
			if len(parts) >= 3 {
				key := parts[1]
				vals := parseQuotedValues(parts[2])
				switch {
				case key == "ssl-exempt-categories" && obj != nil:
					for _, v := range vals {
						id, _ := strconv.Atoi(v)
						obj.ExemptCats = append(obj.ExemptCats, id)
					}
				case key == "fortiguard-category" && exemption != nil:
					exemption.FortiguardCategory, _ = strconv.Atoi(vals[0])
				case key == "type" && exemption != nil:
					exemption.Type = vals[0]
				case key == "wildcard-fqdn" && exemption != nil:
					exemption.WildcardFQDN = vals[0]
				}
			}
		}
		i++
	}
	return i
}

// --- URL Filter Tables ---

func (p *FortiGateParser) parseURLFilterBlock(lines []string, start int) int {
	i := start
	depth := 1
	var table *URLFilterTable
	inEntries := false
	var entry *URLFilterEntry
	for i < len(lines) && depth > 0 {
		s := skipComment(lines[i])
		if s == "" {
			i++
			continue
		}
		if s == "end" {
			if entry != nil && table != nil {
				table.Entries = append(table.Entries, *entry)
				entry = nil
			}
			depth--
			if depth == 1 {
				inEntries = false
			}
			if depth == 0 {
				if table != nil {
					p.URLFilters[table.ID] = table
				}
				return i + 1
			}
			i++
			continue
		}
		if strings.HasPrefix(s, "config ") {
			depth++
			if strings.Contains(s, "entries") {
				inEntries = true
			}
			i++
			continue
		}
		if strings.HasPrefix(s, "edit ") && depth == 1 {
			if table != nil {
				p.URLFilters[table.ID] = table
			}
			idStr := parseQuotedValues(s[5:])[0]
			id, _ := strconv.Atoi(idStr)
			table = &URLFilterTable{ID: id}
			i++
			continue
		}
		if strings.HasPrefix(s, "edit ") && inEntries {
			if entry != nil && table != nil {
				table.Entries = append(table.Entries, *entry)
			}
			entry = &URLFilterEntry{}
			i++
			continue
		}
		if s == "next" {
			if inEntries && entry != nil && table != nil {
				table.Entries = append(table.Entries, *entry)
				entry = nil
			} else if !inEntries && depth == 1 {
				if table != nil {
					p.URLFilters[table.ID] = table
					table = nil
				}
			}
			i++
			continue
		}
		if strings.HasPrefix(s, "set ") {
			parts := splitN(s, 3)
			if len(parts) >= 3 {
				key := parts[1]
				vals := parseQuotedValues(parts[2])
				switch {
				case key == "name" && table != nil && !inEntries:
					table.Name = vals[0]
				case key == "url" && entry != nil:
					entry.URL = vals[0]
				case key == "type" && entry != nil:
					entry.Type = vals[0]
				case key == "action" && entry != nil:
					entry.Action = vals[0]
				}
			}
		}
		i++
	}
	return i
}

// --- Onetime Schedules ---

func (p *FortiGateParser) parseOnetimeScheduleBlock(lines []string, start int) int {
	i := start
	depth := 1
	var obj *OnetimeSchedule
	for i < len(lines) && depth > 0 {
		s := skipComment(lines[i])
		if s == "" {
			i++
			continue
		}
		if s == "end" {
			depth--
			if depth == 0 {
				if obj != nil {
					p.OnetimeSchedules[obj.Name] = obj
				}
				return i + 1
			}
			i++
			continue
		}
		if strings.HasPrefix(s, "config ") {
			depth++
			i++
			continue
		}
		if strings.HasPrefix(s, "edit ") {
			if obj != nil {
				p.OnetimeSchedules[obj.Name] = obj
			}
			name := parseQuotedValues(s[5:])[0]
			obj = &OnetimeSchedule{Name: name}
			i++
			continue
		}
		if s == "next" {
			if obj != nil {
				p.OnetimeSchedules[obj.Name] = obj
				obj = nil
			}
			i++
			continue
		}
		if strings.HasPrefix(s, "set ") && obj != nil {
			parts := splitN(s, 3)
			if len(parts) >= 3 {
				key := parts[1]
				rest := parts[2]
				switch key {
				case "start":
					obj.Start = strings.Trim(rest, `"`)
				case "end":
					obj.End = strings.Trim(rest, `"`)
				}
			}
		}
		i++
	}
	return i
}
