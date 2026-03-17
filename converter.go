package forti2versa

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// VersaConverter converts parsed FortiGate config to Versa template format.
type VersaConverter struct {
	parser    *FortiGateParser
	sanitizer *NameSanitizer
	Report    *ConversionReport

	template   string
	org        string
	policyName string
	zoneMap    map[string]string
	skipOrphans bool
	scheduleMap map[string]string
	secProfileMap map[string]map[string]string

	output []string

	// Converted Versa service names per FG service name
	versaServices map[string][]string
	// Track iprange wrapper group names
	rangeGroups map[string]string
	// Track emitted schedule objects
	emittedSchedules map[string]bool
	// Orphan tracking
	referencedAddrs     map[string]bool
	referencedAddrGrps  map[string]bool
	referencedServices  map[string]bool
	referencedSvcGrps   map[string]bool
	referencedWFQDNs    map[string]bool
	// Generated URL filtering profile names (FG webfilter name -> Versa profile name)
	urlFilterProfiles map[string]string
	// Generated URL monitor profile names (FG webfilter name -> Versa monitor profile name)
	urlMonitorProfiles map[string]string
	// Predefined service mappings (FG service name -> Versa predefined slug)
	versaPredefined map[string]string
	// Addresses that are 0.0.0.0/0 (match-all, omitted from output)
	matchAllAddrs map[string]bool
	// Services that mean "match all" (ALL, IP protocol — omitted from output)
	matchAllSvcs map[string]bool
}

func NewVersaConverter(parser *FortiGateParser, config *Config) *VersaConverter {
	return &VersaConverter{
		parser:            parser,
		sanitizer:         NewNameSanitizer(),
		Report:            NewConversionReport(),
		template:          config.TemplateName,
		org:               config.OrgName,
		policyName:        config.PolicyName,
		zoneMap:           config.InterfaceZoneMap,
		skipOrphans:       config.SkipOrphans,
		scheduleMap:       config.ScheduleMap,
		secProfileMap:     config.SecurityProfileMap,
		versaServices:     make(map[string][]string),
		rangeGroups:       make(map[string]string),
		emittedSchedules:  make(map[string]bool),
		referencedAddrs:   make(map[string]bool),
		referencedAddrGrps: make(map[string]bool),
		referencedServices: make(map[string]bool),
		referencedSvcGrps:  make(map[string]bool),
		referencedWFQDNs:  make(map[string]bool),
		urlFilterProfiles:  make(map[string]string),
		urlMonitorProfiles: make(map[string]string),
		versaPredefined:    make(map[string]string),
		matchAllAddrs:      make(map[string]bool),
		matchAllSvcs:       make(map[string]bool),
	}
}

// Prefix helpers
func (c *VersaConverter) addrPrefix(name string) string {
	return fmt.Sprintf("set devices template %s config orgs org-services %s objects addresses address %s", c.template, c.org, name)
}

func (c *VersaConverter) agrpPrefix(name string) string {
	return fmt.Sprintf("set devices template %s config orgs org-services %s objects address-groups group %s", c.template, c.org, name)
}

func (c *VersaConverter) svcPrefix(name string) string {
	return fmt.Sprintf("set devices template %s config orgs org-services %s objects services service %s", c.template, c.org, name)
}

func (c *VersaConverter) schedPrefix(name string) string {
	return fmt.Sprintf("set devices template %s config orgs org-services %s objects schedules schedule %s", c.template, c.org, name)
}

func (c *VersaConverter) rulePrefix(name string) string {
	return fmt.Sprintf("set devices template %s config orgs org-services %s security access-policies access-policy-group %s rules access-policy %s", c.template, c.org, c.policyName, name)
}

func (c *VersaConverter) urlFilterProfilePrefix(name string) string {
	return fmt.Sprintf("set devices template %s config orgs org-services %s security profiles url-filtering url-filtering-profile %s", c.template, c.org, name)
}

func (c *VersaConverter) decryptProfilePrefix(name string) string {
	return fmt.Sprintf("set devices template %s config orgs org-services %s security profiles decrypt decrypt-profile %s", c.template, c.org, name)
}

func (c *VersaConverter) decryptRulePrefix(name string) string {
	return fmt.Sprintf("set devices template %s config orgs org-services %s security decryption-policies decryption-policy-group %s rules decryption-policy %s", c.template, c.org, c.policyName, name)
}

// Orphan detection
func (c *VersaConverter) collectReferenced() {
	for _, pol := range c.parser.Policies {
		for _, a := range pol.SrcAddr {
			if !strings.EqualFold(a, "all") {
				c.markAddrRef(a)
			}
		}
		for _, a := range pol.DstAddr {
			if !strings.EqualFold(a, "all") {
				c.markAddrRef(a)
			}
		}
		for _, s := range pol.Service {
			c.markSvcRef(s)
		}
	}
	// Mark wildcard-fqdn names referenced in SSL profile exemptions
	for _, prof := range c.parser.SSLSSHProfiles {
		for _, ex := range prof.Exemptions {
			if ex.Type == "wildcard-fqdn" && ex.WildcardFQDN != "" {
				c.markAddrRef(ex.WildcardFQDN)
			}
		}
	}
}

func (c *VersaConverter) markAddrRef(name string) {
	if c.referencedAddrs[name] || c.referencedAddrGrps[name] || c.referencedWFQDNs[name] {
		return
	}
	if _, ok := c.parser.Addresses[name]; ok {
		c.referencedAddrs[name] = true
	} else if grp, ok := c.parser.AddrGroups[name]; ok {
		c.referencedAddrGrps[name] = true
		for _, m := range grp.Members {
			c.markAddrRef(m)
		}
	} else if _, ok := c.parser.WildcardFQDNs[name]; ok {
		c.referencedWFQDNs[name] = true
	}
}

func (c *VersaConverter) markSvcRef(name string) {
	if c.referencedServices[name] || c.referencedSvcGrps[name] {
		return
	}
	if _, ok := c.parser.Services[name]; ok {
		c.referencedServices[name] = true
	} else if grp, ok := c.parser.SvcGroups[name]; ok {
		c.referencedSvcGrps[name] = true
		for _, m := range grp.Members {
			c.markSvcRef(m)
		}
	}
}

func (c *VersaConverter) isOrphanAddr(name string) bool {
	return !c.referencedAddrs[name] && !c.referencedAddrGrps[name]
}

func (c *VersaConverter) isOrphanAddrGroup(name string) bool {
	return !c.referencedAddrGrps[name]
}

func (c *VersaConverter) isOrphanService(name string) bool {
	return !c.referencedServices[name]
}

// validateProfileMap checks security_profile_map values against Versa predefined names.
func (c *VersaConverter) validateProfileMap() {
	validators := map[string]map[string]bool{
		"av-profile":       VersaAVProfiles,
		"ips-sensor":       VersaIPSProfiles,
		"webfilter-profile": VersaURLFilteringProfiles,
		"dnsfilter-profile": VersaDNSFilteringProfiles,
	}
	for section, profiles := range c.secProfileMap {
		valid, ok := validators[section]
		if !ok {
			continue
		}
		for fgName, versaName := range profiles {
			if !valid[versaName] {
				c.Report.AddWarning(fmt.Sprintf("security_profile_map[%s][%s] = \"%s\" is not a valid Versa predefined profile name — check case/spelling", section, fgName, versaName))
			}
		}
	}
}

// Convert runs the full conversion pipeline.
func (c *VersaConverter) Convert() string {
	c.validateProfileMap()
	c.collectReferenced()
	c.convertAddresses()
	c.convertWildcardFQDNs()
	c.convertAddressGroups()
	c.convertServices()
	c.convertSchedules()
	c.convertURLFilteringProfiles()
	c.convertPolicies()
	c.convertDecryptionPolicies()
	return strings.Join(c.output, "\n")
}

// --- Schedules ---
func (c *VersaConverter) convertSchedules() {
	for _, pol := range c.parser.Policies {
		sched := pol.Schedule
		if sched == "" || sched == "always" {
			continue
		}
		vname := c.sanitizer.Sanitize(sched)
		if c.emittedSchedules[vname] {
			continue
		}
		c.emittedSchedules[vname] = true

		// Check onetime schedules first
		if ot, ok := c.parser.OnetimeSchedules[sched]; ok {
			versaRange := convertOnetimeRange(ot.Start, ot.End)
			c.output = append(c.output, fmt.Sprintf("%s non-recurring %s", c.schedPrefix(vname), versaRange))
			c.Report.AddConverted(fmt.Sprintf("schedule \"%s\" -> %s (non-recurring %s)", sched, vname, versaRange))
			continue
		}

		if timeRange, ok := c.scheduleMap[sched]; ok {
			c.output = append(c.output, fmt.Sprintf("%s recurring daily time-of-day %s", c.schedPrefix(vname), timeRange))
			c.Report.AddConverted(fmt.Sprintf("schedule \"%s\" -> %s (daily %s)", sched, vname, timeRange))
		} else {
			c.output = append(c.output, fmt.Sprintf("%s recurring daily time-of-day 08:00-17:00", c.schedPrefix(vname)))
			c.Report.AddWarning(fmt.Sprintf("Schedule \"%s\": no time range defined in schedule_map — emitted placeholder 08:00-17:00, adjust in config or output", sched))
			c.Report.AddConverted(fmt.Sprintf("schedule \"%s\" -> %s (placeholder 08:00-17:00)", sched, vname))
		}
	}
}

// convertOnetimeRange converts FortiGate "HH:MM YYYY/MM/DD" to Versa "YYYY/MM/DD@HH:MM".
func convertOnetimeRange(start, end string) string {
	return convertOnetimeTS(start) + "-" + convertOnetimeTS(end)
}

func convertOnetimeTS(ts string) string {
	// FortiGate format: "HH:MM YYYY/MM/DD"
	parts := strings.Fields(ts)
	if len(parts) == 2 {
		return parts[1] + "@" + parts[0]
	}
	return ts
}

// --- URL Filtering Profiles ---
func (c *VersaConverter) convertURLFilteringProfiles() {
	// Collect unique webfilter profiles referenced by policies
	seen := make(map[string]bool)
	for _, pol := range c.parser.Policies {
		if pol.WebfilterProfile == "" || seen[pol.WebfilterProfile] {
			continue
		}
		seen[pol.WebfilterProfile] = true

		wf, ok := c.parser.WebfilterProfiles[pol.WebfilterProfile]
		if !ok {
			continue
		}

		// Group categories by action
		blockCats := []string{}
		monitorCats := []string{}
		for _, cat := range wf.Categories {
			versaSlug, ok := FGCategoryToVersa[cat.ID]
			if !ok {
				c.Report.AddWarning(fmt.Sprintf("Webfilter \"%s\": FortiGate category ID %d has no Versa mapping", pol.WebfilterProfile, cat.ID))
				continue
			}
			if !VersaURLCategories[versaSlug] {
				c.Report.AddWarning(fmt.Sprintf("Webfilter \"%s\": Versa category slug \"%s\" (from FG cat %d) is not a valid predefined URL category", pol.WebfilterProfile, versaSlug, cat.ID))
				continue
			}
			switch cat.Action {
			case "block":
				blockCats = append(blockCats, versaSlug)
			case "monitor", "warning":
				monitorCats = append(monitorCats, versaSlug)
			}
		}

		// Check if profile has URL filter table patterns (even if no categories)
		hasURLFilterTable := wf.URLFilterTable > 0 && c.parser.URLFilters[wf.URLFilterTable] != nil
		blacklistPatterns, whitelistPatterns, monitorPatterns := c.getURLFilterPatterns(wf)

		if len(blockCats) == 0 && len(monitorCats) == 0 && !hasURLFilterTable {
			continue
		}

		// Deduplicate categories (multiple FG IDs can map to same Versa slug)
		blockCats = dedup(blockCats)
		monitorCats = dedup(monitorCats)

		profileName := c.sanitizer.Sanitize(pol.WebfilterProfile)
		c.urlFilterProfiles[pol.WebfilterProfile] = profileName

		pp := c.urlFilterProfilePrefix(profileName)
		c.output = append(c.output, pp+" cloud-lookup disabled")
		c.output = append(c.output, pp+" decrypt-bypass false")

		// Blacklist section
		if len(blacklistPatterns) > 0 {
			c.output = append(c.output, fmt.Sprintf("%s blacklist patterns [ %s ]", pp, strings.Join(blacklistPatterns, " ")))
		}
		c.output = append(c.output, pp+" blacklist evaluate-referrer true")

		// Whitelist section
		if len(whitelistPatterns) > 0 {
			c.output = append(c.output, fmt.Sprintf("%s whitelist patterns [ %s ]", pp, strings.Join(whitelistPatterns, " ")))
		}
		c.output = append(c.output, pp+" whitelist log-enable false")
		c.output = append(c.output, pp+" whitelist evaluate-referrer true")

		if len(blockCats) > 0 {
			actionName := profileName + "_block"
			if len(actionName) > 63 {
				actionName = actionName[:63]
			}
			c.output = append(c.output, fmt.Sprintf("%s category-action-map category-action %s url-categories predefined [ %s ]",
				pp, actionName, strings.Join(blockCats, " ")))
			c.output = append(c.output, fmt.Sprintf("%s category-action-map category-action %s action predefined block",
				pp, actionName))
		}

		if len(monitorCats) > 0 {
			actionName := profileName + "_monitor"
			if len(actionName) > 63 {
				actionName = actionName[:63]
			}
			c.output = append(c.output, fmt.Sprintf("%s category-action-map category-action %s url-categories predefined [ %s ]",
				pp, actionName, strings.Join(monitorCats, " ")))
			c.output = append(c.output, fmt.Sprintf("%s category-action-map category-action %s action predefined monitor",
				pp, actionName))
		}

		c.Report.AddConverted(fmt.Sprintf("url-filtering-profile \"%s\" -> %s (%d block, %d monitor categories)",
			pol.WebfilterProfile, profileName, len(blockCats), len(monitorCats)))

		// Emit separate monitor URL filtering profile (whitelist + logging)
		if len(monitorPatterns) > 0 {
			monProfileName := profileName + "_url_monitor"
			if len(monProfileName) > 63 {
				monProfileName = monProfileName[:63]
			}
			c.urlMonitorProfiles[pol.WebfilterProfile] = monProfileName

			mp := c.urlFilterProfilePrefix(monProfileName)
			c.output = append(c.output, mp+" cloud-lookup disabled")
			c.output = append(c.output, mp+" decrypt-bypass false")
			c.output = append(c.output, mp+" blacklist evaluate-referrer true")
			c.output = append(c.output, fmt.Sprintf("%s whitelist patterns [ %s ]", mp, strings.Join(monitorPatterns, " ")))
			c.output = append(c.output, mp+" whitelist log-enable true")
			c.output = append(c.output, mp+" whitelist evaluate-referrer true")

			c.Report.AddConverted(fmt.Sprintf("url-filtering-profile \"%s\" (monitor URLs -> whitelist with logging)", monProfileName))
		}
	}
}

// getURLFilterPatterns collects blacklist, whitelist, and monitor regex patterns from a webfilter's urlfilter-table.
func (c *VersaConverter) getURLFilterPatterns(wf *WebfilterProfile) (blacklist, whitelist, monitor []string) {
	if wf.URLFilterTable <= 0 {
		return
	}
	table, ok := c.parser.URLFilters[wf.URLFilterTable]
	if !ok {
		return
	}
	for _, entry := range table.Entries {
		pattern := fortiURLToVersaRegex(entry.URL, entry.Type)
		quoted := fmt.Sprintf("%q", pattern)
		switch entry.Action {
		case "block":
			blacklist = append(blacklist, quoted)
		case "monitor":
			monitor = append(monitor, quoted)
		case "allow", "exempt":
			whitelist = append(whitelist, quoted)
		}
	}
	return
}

// fortiURLToVersaRegex converts a FortiGate URL filter pattern to a Versa regex pattern.
func fortiURLToVersaRegex(url, urlType string) string {
	switch urlType {
	case "regex":
		return url
	case "simple":
		// Simple URL: escape dots, prefix with .*
		escaped := strings.ReplaceAll(url, ".", `\.`)
		return ".*" + escaped
	default: // "wildcard" or unset
		// Wildcard URL: replace * with .*, escape dots in remainder
		// First replace * with a placeholder, escape dots, then restore .*
		result := strings.ReplaceAll(url, "*", "\x00")
		result = strings.ReplaceAll(result, ".", `\.`)
		result = strings.ReplaceAll(result, "\x00", ".*")
		return result
	}
}

func dedup(in []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// --- Addresses ---
func (c *VersaConverter) convertAddresses() {
	for _, name := range c.parser.AddrOrder {
		obj := c.parser.Addresses[name]
		if c.skipOrphans && c.isOrphanAddr(name) {
			c.Report.AddSkipped(fmt.Sprintf("address \"%s\" (orphan)", name))
			continue
		}

		if obj.Type == "geography" {
			c.Report.AddConverted(fmt.Sprintf("address \"%s\" -> geolocation country %s (inline in rules)", name, obj.Country))
			continue
		}

		vname := c.sanitizer.Sanitize(name)
		if c.sanitizer.WasRenamed(name) {
			c.Report.AddWarning(fmt.Sprintf("Address renamed: \"%s\" -> \"%s\"", name, vname))
		}

		switch obj.Type {
		case "ipmask":
			cidr := subnetToCIDR(obj.Subnet)
			if cidr == "0.0.0.0/0" {
				c.matchAllAddrs[name] = true
				c.Report.AddConverted(fmt.Sprintf("address \"%s\" -> match-all (0.0.0.0/0, omitted)", name))
				continue
			}
			c.output = append(c.output, fmt.Sprintf("%s ipv4-prefix %s", c.addrPrefix(vname), cidr))
			c.Report.AddConverted(fmt.Sprintf("address \"%s\" -> %s (ipmask %s)", name, vname, cidr))
		case "fqdn":
			c.output = append(c.output, fmt.Sprintf("%s fqdn %s", c.addrPrefix(vname), obj.FQDN))
			c.Report.AddConverted(fmt.Sprintf("address \"%s\" -> %s (fqdn %s)", name, vname, obj.FQDN))
		case "iprange":
			c.convertIPRange(name, obj)
		}
	}
}

func subnetToCIDR(subnetStr string) string {
	parts := strings.Fields(subnetStr)
	if len(parts) != 2 {
		return subnetStr
	}
	ip := net.ParseIP(parts[0])
	mask := net.ParseIP(parts[1])
	if ip == nil || mask == nil {
		return subnetStr
	}
	ip = ip.To4()
	mask = mask.To4()
	if ip == nil || mask == nil {
		return subnetStr
	}
	ones, _ := net.IPMask(mask).Size()
	// Apply mask to IP to get network address
	network := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		network[i] = ip[i] & mask[i]
	}
	return fmt.Sprintf("%s/%d", network, ones)
}

func (c *VersaConverter) convertIPRange(name string, obj *AddressObj) {
	start, err := netip.ParseAddr(obj.StartIP)
	if err != nil {
		c.Report.AddWarning(fmt.Sprintf("IP range \"%s\" has invalid IPs, skipping", name))
		return
	}
	end, err := netip.ParseAddr(obj.EndIP)
	if err != nil {
		c.Report.AddWarning(fmt.Sprintf("IP range \"%s\" has invalid IPs, skipping", name))
		return
	}
	cidrs := summarizeRange(start, end)
	if len(cidrs) == 0 {
		c.Report.AddWarning(fmt.Sprintf("IP range \"%s\" has invalid IPs, skipping", name))
		return
	}

	vname := c.sanitizer.Sanitize(name)
	if c.sanitizer.WasRenamed(name) {
		c.Report.AddWarning(fmt.Sprintf("Address renamed: \"%s\" -> \"%s\"", name, vname))
	}

	if len(cidrs) == 1 {
		c.output = append(c.output, fmt.Sprintf("%s ipv4-prefix %s", c.addrPrefix(vname), cidrs[0]))
		c.Report.AddConverted(fmt.Sprintf("address \"%s\" -> %s (iprange -> %s)", name, vname, cidrs[0]))
	} else {
		var subNames []string
		for idx, cidr := range cidrs {
			subNameRaw := fmt.Sprintf("%s-cidr%d", name, idx+1)
			subVName := c.sanitizer.Sanitize(subNameRaw)
			subNames = append(subNames, subVName)
			c.output = append(c.output, fmt.Sprintf("%s ipv4-prefix %s", c.addrPrefix(subVName), cidr))
		}
		grpVName := vname
		membersStr := strings.Join(subNames, " ")
		c.output = append(c.output, fmt.Sprintf("%s address-list [ %s ]", c.agrpPrefix(grpVName), membersStr))
		c.output = append(c.output, fmt.Sprintf("%s type static", c.agrpPrefix(grpVName)))
		c.rangeGroups[name] = grpVName
		c.Report.AddConverted(fmt.Sprintf("address \"%s\" -> group %s (%d CIDRs)", name, grpVName, len(cidrs)))
		c.Report.AddWarning(fmt.Sprintf("IP range \"%s\" expanded to %d CIDRs with wrapper group \"%s\"", name, len(cidrs), grpVName))
	}
}

// --- Wildcard FQDNs ---
func (c *VersaConverter) convertWildcardFQDNs() {
	if len(c.parser.WildcardFQDNs) == 0 {
		return
	}
	warnedDNSProxy := false
	for _, name := range c.parser.WFQDNOrder {
		obj := c.parser.WildcardFQDNs[name]
		if c.skipOrphans && !c.referencedWFQDNs[name] {
			c.Report.AddSkipped(fmt.Sprintf("wildcard-fqdn \"%s\" (orphan)", name))
			continue
		}
		vname := c.sanitizer.Sanitize(name)
		if c.sanitizer.WasRenamed(name) {
			c.Report.AddWarning(fmt.Sprintf("Wildcard-FQDN renamed: \"%s\" -> \"%s\"", name, vname))
		}
		c.output = append(c.output, fmt.Sprintf("%s fqdn %s", c.addrPrefix(vname), obj.WildcardFQDN))
		c.Report.AddConverted(fmt.Sprintf("wildcard-fqdn \"%s\" -> %s (fqdn %s)", name, vname, obj.WildcardFQDN))
		if !warnedDNSProxy {
			c.Report.AddWarning("Wildcard FQDN objects require DNS Proxy enabled on VOS")
			warnedDNSProxy = true
		}
	}
}

// --- Address Groups ---
func (c *VersaConverter) convertAddressGroups() {
	for _, name := range c.parser.AGrpOrder {
		grp := c.parser.AddrGroups[name]
		if c.skipOrphans && c.isOrphanAddrGroup(name) {
			c.Report.AddSkipped(fmt.Sprintf("address-group \"%s\" (orphan)", name))
			continue
		}

		vname := c.sanitizer.Sanitize(name)
		if c.sanitizer.WasRenamed(name) {
			c.Report.AddWarning(fmt.Sprintf("Address group renamed: \"%s\" -> \"%s\"", name, vname))
		}

		var addrMembers, groupMembers []string
		for _, m := range grp.Members {
			if _, ok := c.parser.AddrGroups[m]; ok {
				groupMembers = append(groupMembers, c.sanitizer.Sanitize(m))
			} else if obj, ok := c.parser.Addresses[m]; ok {
				if obj.Type == "geography" {
					c.Report.AddWarning(fmt.Sprintf("Skipping geography member \"%s\" in group \"%s\"", m, name))
					continue
				}
				if rg, ok := c.rangeGroups[m]; ok {
					groupMembers = append(groupMembers, rg)
				} else {
					addrMembers = append(addrMembers, c.sanitizer.Sanitize(m))
				}
			} else if _, ok := c.parser.WildcardFQDNs[m]; ok {
				addrMembers = append(addrMembers, c.sanitizer.Sanitize(m))
			} else {
				addrMembers = append(addrMembers, c.sanitizer.Sanitize(m))
				c.Report.AddWarning(fmt.Sprintf("Unknown member \"%s\" in group \"%s\" - treating as address", m, name))
			}
		}

		if len(addrMembers) > 0 {
			c.output = append(c.output, fmt.Sprintf("%s address-list [ %s ]", c.agrpPrefix(vname), strings.Join(addrMembers, " ")))
		}
		if len(groupMembers) > 0 {
			c.output = append(c.output, fmt.Sprintf("%s address-group-list [ %s ]", c.agrpPrefix(vname), strings.Join(groupMembers, " ")))
		}
		c.output = append(c.output, fmt.Sprintf("%s type static", c.agrpPrefix(vname)))
		c.Report.AddConverted(fmt.Sprintf("address-group \"%s\" -> %s (%d addrs, %d groups)", name, vname, len(addrMembers), len(groupMembers)))
	}
}

// --- Services ---
func (c *VersaConverter) convertServices() {
	for _, name := range c.parser.SvcOrder {
		obj := c.parser.Services[name]
		if c.skipOrphans && c.isOrphanService(name) {
			c.Report.AddSkipped(fmt.Sprintf("service \"%s\" (orphan)", name))
			continue
		}
		c.convertOneService(name, obj)
	}
}

func (c *VersaConverter) convertOneService(name string, obj *ServiceObj) {
	// Check predefined mapping first (skip custom creation for standard services)
	if versaPre, ok := FGServiceToVersaPredefined[name]; ok {
		c.versaPredefined[name] = versaPre
		c.Report.AddConverted(fmt.Sprintf("service \"%s\" -> predefined %s", name, versaPre))
		return
	}

	vname := c.sanitizer.Sanitize(name)
	if c.sanitizer.WasRenamed(name) {
		c.Report.AddWarning(fmt.Sprintf("Service renamed: \"%s\" -> \"%s\"", name, vname))
	}

	// ALL / IP protocol -> match-all (omit from output, Versa matches all when no service constraint)
	if obj.Protocol == "IP" || name == "ALL" {
		c.matchAllSvcs[name] = true
		c.Report.AddConverted(fmt.Sprintf("service \"%s\" -> match-all (omitted)", name))
		return
	}

	protos := strings.Fields(strings.ToUpper(obj.Protocol))
	hasTCP := contains(protos, "TCP")
	hasUDP := contains(protos, "UDP")
	isDual := hasTCP && hasUDP

	var generated []string

	if hasTCP && obj.TCPPortRange != "" {
		tcpSvcs := c.expandPortEntries(name, vname, "TCP", obj.TCPPortRange, isDual)
		generated = append(generated, tcpSvcs...)
	}
	if hasUDP && obj.UDPPortRange != "" {
		udpSvcs := c.expandPortEntries(name, vname, "UDP", obj.UDPPortRange, isDual)
		generated = append(generated, udpSvcs...)
	}

	if len(generated) == 0 {
		c.output = append(c.output, fmt.Sprintf("%s protocol %s", c.svcPrefix(vname), protos[0]))
		generated = append(generated, vname)
		c.Report.AddConverted(fmt.Sprintf("service \"%s\" -> %s (%s, no port)", name, vname, protos[0]))
	}

	c.versaServices[name] = generated
}

func (c *VersaConverter) expandPortEntries(origName, baseVName, proto, portrange string, isDual bool) []string {
	entries := strings.Fields(portrange)
	var generated []string

	for _, entry := range entries {
		dstPart := entry
		if idx := strings.Index(entry, ":"); idx >= 0 {
			dstPart = entry[:idx]
			srcPart := entry[idx+1:]
			c.Report.AddWarning(fmt.Sprintf("Service \"%s\": dropping source port constraint \"%s\" for entry \"%s\"", origName, srcPart, entry))
		}

		var svcVName string
		if len(entries) == 1 && !isDual {
			svcVName = baseVName
		} else if len(entries) == 1 && isDual {
			raw := origName + "-" + proto
			svcVName = c.sanitizer.Sanitize(raw)
		} else {
			if isDual {
				raw := origName + "-" + proto + "-p" + dstPart
				svcVName = c.sanitizer.Sanitize(raw)
			} else {
				raw := origName + "-p" + dstPart
				svcVName = c.sanitizer.Sanitize(raw)
			}
		}

		c.output = append(c.output, fmt.Sprintf("%s protocol %s", c.svcPrefix(svcVName), proto))
		c.output = append(c.output, fmt.Sprintf("%s destination-port %s", c.svcPrefix(svcVName), dstPart))
		generated = append(generated, svcVName)
		c.Report.AddConverted(fmt.Sprintf("service \"%s\" -> %s (%s/%s)", origName, svcVName, proto, dstPart))
	}
	return generated
}

// flattenSvcGroup recursively flattens a service group to leaf Versa service names.
func (c *VersaConverter) flattenSvcGroup(name string) []string {
	if _, ok := c.parser.Services[name]; ok {
		if vs, ok := c.versaServices[name]; ok {
			return vs
		}
		return []string{c.sanitizer.Sanitize(name)}
	}
	if grp, ok := c.parser.SvcGroups[name]; ok {
		var result []string
		for _, m := range grp.Members {
			result = append(result, c.flattenSvcGroup(m)...)
		}
		return result
	}
	return []string{c.sanitizer.Sanitize(name)}
}

// --- Policies ---
func (c *VersaConverter) convertPolicies() {
	for _, pol := range c.parser.Policies {
		vname := c.sanitizer.Sanitize(pol.Name)
		if c.sanitizer.WasRenamed(pol.Name) {
			c.Report.AddWarning(fmt.Sprintf("Policy renamed: \"%s\" -> \"%s\"", pol.Name, vname))
		}

		// Emit monitor-URL rule before main rule (if webfilter has monitor URL entries)
		if monProfile, ok := c.urlMonitorProfiles[pol.WebfilterProfile]; ok {
			c.emitMonitorURLRule(pol, vname, monProfile)
		}

		rp := c.rulePrefix(vname)

		c.output = append(c.output, rp+" rule-disable false")

		// Description
		if pol.Comments != "" {
			escaped := strings.ReplaceAll(pol.Comments, `"`, `\"`)
			c.output = append(c.output, fmt.Sprintf("%s description \"%s\"", rp, escaped))
		}

		// Source zone
		if srcZone, ok := c.zoneMap[pol.SrcIntf]; ok {
			c.output = append(c.output, fmt.Sprintf("%s match source zone zone-list [ %s ]", rp, srcZone))
		} else if pol.SrcIntf != "" {
			c.Report.AddWarning(fmt.Sprintf("Policy \"%s\": unmapped source interface \"%s\"", pol.Name, pol.SrcIntf))
			fallback := c.sanitizer.Sanitize(pol.SrcIntf)
			c.output = append(c.output, fmt.Sprintf("%s match source zone zone-list [ %s ]", rp, fallback))
		}

		// Source addresses
		c.emitAddrMatch(rp, "source", pol.SrcAddr)

		// User/group stanzas
		if len(pol.Users) > 0 || len(pol.Groups) > 0 {
			c.output = append(c.output, rp+" match source user local-database status enabled")
			if len(pol.Groups) > 0 {
				var sanitizedGroups []string
				for _, g := range pol.Groups {
					sanitizedGroups = append(sanitizedGroups, c.sanitizer.Sanitize(g))
				}
				c.output = append(c.output, fmt.Sprintf("%s match source user local-database group-list [ %s ]", rp, strings.Join(sanitizedGroups, " ")))
			}
			if len(pol.Users) > 0 {
				var sanitizedUsers []string
				for _, u := range pol.Users {
					sanitizedUsers = append(sanitizedUsers, c.sanitizer.Sanitize(u))
				}
				c.output = append(c.output, fmt.Sprintf("%s match source user local-database user-list [ %s ]", rp, strings.Join(sanitizedUsers, " ")))
			}
			c.output = append(c.output, rp+" match source user external-database status disabled")
			c.output = append(c.output, rp+" match source user user-type selected")
		} else {
			c.output = append(c.output, rp+" match source user local-database status disabled")
			c.output = append(c.output, rp+" match source user external-database status disabled")
			c.output = append(c.output, rp+" match source user user-type any")
		}

		// Destination zone
		if dstZone, ok := c.zoneMap[pol.DstIntf]; ok {
			c.output = append(c.output, fmt.Sprintf("%s match destination zone zone-list [ %s ]", rp, dstZone))
		} else if pol.DstIntf != "" {
			c.Report.AddWarning(fmt.Sprintf("Policy \"%s\": unmapped destination interface \"%s\"", pol.Name, pol.DstIntf))
			fallback := c.sanitizer.Sanitize(pol.DstIntf)
			c.output = append(c.output, fmt.Sprintf("%s match destination zone zone-list [ %s ]", rp, fallback))
		}

		// Destination addresses
		c.emitAddrMatch(rp, "destination", pol.DstAddr)

		// Services (resolve to custom and/or predefined; omit entirely for match-all)
		if len(pol.Service) > 0 && !c.isMatchAllService(pol.Service) {
			customSvcs, predefinedSvcs := c.resolvePolicyServices(pol)
			if len(customSvcs) > 0 {
				c.output = append(c.output, fmt.Sprintf("%s match services services-list [ %s ]", rp, strings.Join(customSvcs, " ")))
			}
			if len(predefinedSvcs) > 0 {
				c.output = append(c.output, fmt.Sprintf("%s match services predefined-services-list [ %s ]", rp, strings.Join(predefinedSvcs, " ")))
			}
		}

		// Schedule
		if pol.Schedule != "" && pol.Schedule != "always" {
			schedVName := c.sanitizer.Sanitize(pol.Schedule)
			c.output = append(c.output, fmt.Sprintf("%s match schedule %s", rp, schedVName))
		}

		// URL category match
		c.emitURLCategoryMatch(rp, pol)

		// Security profiles (enforce section)
		c.emitSecurityProfiles(rp, pol)

		// Action
		versaAction := "allow"
		if pol.Action != "accept" {
			versaAction = "deny"
		}
		c.output = append(c.output, fmt.Sprintf("%s set action %s", rp, versaAction))

		// TCP session keepalive
		c.output = append(c.output, rp+" set tcp-session-keepalive disabled")

		// LEF (logging)
		c.output = append(c.output, rp+" set lef profile-default true")
		switch pol.LogTraffic {
		case "all", "utm":
			c.output = append(c.output, rp+" set lef event both")
		default:
			c.output = append(c.output, rp+" set lef event end")
		}
		c.output = append(c.output, rp+" set lef options send-pcap-data enable false")
		c.output = append(c.output, rp+" set set-type public")

		// Informational warnings
		if len(pol.Groups) > 0 {
			var sg []string
			for _, g := range pol.Groups {
				sg = append(sg, c.sanitizer.Sanitize(g))
			}
			c.Report.AddWarning(fmt.Sprintf("Policy \"%s\": groups mapped to local-database group-list [ %s ]", pol.Name, strings.Join(sg, " ")))
		}
		if len(pol.Users) > 0 {
			var su []string
			for _, u := range pol.Users {
				su = append(su, c.sanitizer.Sanitize(u))
			}
			c.Report.AddWarning(fmt.Sprintf("Policy \"%s\": users mapped to local-database user-list [ %s ]", pol.Name, strings.Join(su, " ")))
		}
		if pol.NAT == "enable" {
			c.Report.AddWarning(fmt.Sprintf("Policy \"%s\": NAT enabled - requires separate CGNAT config in Versa", pol.Name))
		}
		if pol.SSLSSHProfile != "" {
			if pol.SSLSSHProfile == "deep-inspection" || pol.SSLSSHProfile == "SSL_Inspection" {
				c.Report.AddWarning(fmt.Sprintf("Policy \"%s\": ssl-ssh-profile \"%s\" -> decryption policy rule generated", pol.Name, pol.SSLSSHProfile))
			} else {
				c.Report.AddWarning(fmt.Sprintf("Policy \"%s\": ssl-ssh-profile \"%s\" -> skipped (Versa filters HTTPS natively)", pol.Name, pol.SSLSSHProfile))
			}
		}
		if pol.TrafficShaper != "" {
			c.Report.AddWarning(fmt.Sprintf("Policy \"%s\": traffic-shaper \"%s\" — Versa QoS uses Class of Service; requires manual config", pol.Name, pol.TrafficShaper))
		}

		c.Report.AddConverted(fmt.Sprintf("policy %d \"%s\" -> rule %s", pol.ID, pol.Name, vname))
	}
}

// --- Monitor URL Rules ---
func (c *VersaConverter) emitMonitorURLRule(pol *PolicyObj, vname, monProfile string) {
	ruleName := "monitor-" + vname
	if len(ruleName) > 63 {
		ruleName = strings.TrimRight(strings.TrimRight(ruleName[:63], "-"), "_")
	}

	rp := c.rulePrefix(ruleName)

	c.output = append(c.output, rp+" rule-disable false")

	// Source zone
	if srcZone, ok := c.zoneMap[pol.SrcIntf]; ok {
		c.output = append(c.output, fmt.Sprintf("%s match source zone zone-list [ %s ]", rp, srcZone))
	}

	// User stanzas (disabled — monitor rule is zone-based)
	c.output = append(c.output, rp+" match source user local-database status disabled")
	c.output = append(c.output, rp+" match source user external-database status disabled")
	c.output = append(c.output, rp+" match source user user-type any")

	// Destination zone
	if dstZone, ok := c.zoneMap[pol.DstIntf]; ok {
		c.output = append(c.output, fmt.Sprintf("%s match destination zone zone-list [ %s ]", rp, dstZone))
	}

	// Match HTTPS only
	c.output = append(c.output, rp+" match services predefined-services-list [ https ]")

	// URL filtering profile (whitelist with logging)
	c.output = append(c.output, fmt.Sprintf("%s set security-profile url-filtering user-defined %s", rp, monProfile))

	// Action allow + logging
	c.output = append(c.output, rp+" set action allow")
	c.output = append(c.output, rp+" set lef profile-default true")
	c.output = append(c.output, rp+" set lef event both")
	c.output = append(c.output, rp+" set lef options send-pcap-data enable false")
	c.output = append(c.output, rp+" set set-type public")

	c.Report.AddConverted(fmt.Sprintf("monitor-rule \"%s\" for policy \"%s\" (URL monitor -> allow with logging)", ruleName, pol.Name))
}

// --- Decryption Policies ---
func (c *VersaConverter) convertDecryptionPolicies() {
	deepProfiles := map[string]bool{"deep-inspection": true, "SSL_Inspection": true}

	hasDeep := false
	for _, pol := range c.parser.Policies {
		if pol.SSLSSHProfile != "" && deepProfiles[pol.SSLSSHProfile] {
			hasDeep = true
			break
		}
	}
	if !hasDeep {
		return
	}

	// Emit single decrypt profile
	profileName := "ssl-decrypt-profile"
	pp := c.decryptProfilePrefix(profileName)
	certVar := fmt.Sprintf("{$v_%s_Decryption_Profile_%s_certificate__decryptProfileCertificate}", c.org, profileName)
	caChainVar := fmt.Sprintf("{$v_%s_Decryption_Profile_%s_trusted_certificate__decryptProfileTrustedCertificate}", c.org, profileName)
	c.output = append(c.output,
		pp+" state enabled",
		pp+" decrypt-profile-type ssl-forward-proxy",
		fmt.Sprintf("%s certificate \"%s\"", pp, certVar),
		fmt.Sprintf("%s ca-chain \"%s\"", pp, caChainVar),
		pp+" ssl-protocol-cfg protocol min-version tls-1.1",
		pp+" ssl-protocol-cfg protocol max-version tls-1.2",
		pp+" use-extended-master-secret true",
		pp+" min-supported-key-length 512",
		pp+" restrict-certificate-extension true",
		pp+" support-session-ticket false",
		pp+" lef-profile Default-Logging-Profile",
		pp+" lef-log-level alert",
		pp+" download-ca-issuer disabled",
		pp+" crl-check disabled",
		pp+" ocsp enabled disabled",
		pp+" ocsp response-timeout 5",
		pp+" ocsp ocsp-action drop",
	)
	c.Report.AddConverted(fmt.Sprintf("decrypt-profile -> %s (ssl-forward-proxy)", profileName))
	c.Report.AddWarning("Decrypt profile uses template variables for certificate/ca-chain — provision in Versa Director")

	// Emit no-decrypt rules (SSL exemptions) BEFORE decrypt rules
	for _, pol := range c.parser.Policies {
		if pol.SSLSSHProfile == "" || !deepProfiles[pol.SSLSSHProfile] {
			continue
		}

		exemptCats, exemptFQDNs := c.collectSSLExemptions(pol.SSLSSHProfile)
		if len(exemptCats) == 0 && len(exemptFQDNs) == 0 {
			continue
		}

		vname := c.sanitizer.Sanitize(pol.Name)
		ruleName := "nodecrypt-" + vname
		if len(ruleName) > 63 {
			ruleName = strings.TrimRight(strings.TrimRight(ruleName[:63], "-"), "_")
		}

		rp := c.decryptRulePrefix(ruleName)

		c.output = append(c.output, rp+" rule-disable false")

		// Source zone
		if srcZone, ok := c.zoneMap[pol.SrcIntf]; ok {
			c.output = append(c.output, fmt.Sprintf("%s match source zone zone-list [ %s ]", rp, srcZone))
		}

		// Source user stanzas (always disabled for decrypt rules)
		c.output = append(c.output, rp+" match source user local-database status disabled")
		c.output = append(c.output, rp+" match source user external-database status disabled")
		c.output = append(c.output, rp+" match source user user-type any")

		// Destination zone
		if dstZone, ok := c.zoneMap[pol.DstIntf]; ok {
			c.output = append(c.output, fmt.Sprintf("%s match destination zone zone-list [ %s ]", rp, dstZone))
		}

		// Destination addresses (FQDN exemptions)
		if len(exemptFQDNs) > 0 {
			c.output = append(c.output, fmt.Sprintf("%s match destination address address-list [ %s ]", rp, strings.Join(exemptFQDNs, " ")))
		}

		// Services
		c.output = append(c.output, rp+" match services predefined-services-list [ https ]")

		// URL category exemptions
		if len(exemptCats) > 0 {
			c.output = append(c.output, fmt.Sprintf("%s match url-category predefined [ %s ]", rp, strings.Join(exemptCats, " ")))
		}

		// Action — allow without decryption
		c.output = append(c.output, rp+" set action allow")

		c.Report.AddConverted(fmt.Sprintf("decryption-rule \"%s\" for policy \"%s\" (ssl-exempt -> allow without decryption)", ruleName, pol.Name))
	}

	// Emit decrypt rules
	for _, pol := range c.parser.Policies {
		if pol.SSLSSHProfile == "" || !deepProfiles[pol.SSLSSHProfile] {
			continue
		}

		vname := c.sanitizer.Sanitize(pol.Name)
		ruleName := "decrypt-" + vname
		if len(ruleName) > 63 {
			ruleName = strings.TrimRight(strings.TrimRight(ruleName[:63], "-"), "_")
		}

		rp := c.decryptRulePrefix(ruleName)

		c.output = append(c.output, rp+" rule-disable false")

		// Source zone
		if srcZone, ok := c.zoneMap[pol.SrcIntf]; ok {
			c.output = append(c.output, fmt.Sprintf("%s match source zone zone-list [ %s ]", rp, srcZone))
		}

		// Source user stanzas (always disabled for decrypt rules)
		c.output = append(c.output, rp+" match source user local-database status disabled")
		c.output = append(c.output, rp+" match source user external-database status disabled")
		c.output = append(c.output, rp+" match source user user-type any")

		// Destination zone
		if dstZone, ok := c.zoneMap[pol.DstIntf]; ok {
			c.output = append(c.output, fmt.Sprintf("%s match destination zone zone-list [ %s ]", rp, dstZone))
		}

		// Services
		c.output = append(c.output, rp+" match services predefined-services-list [ https ]")

		// Action
		c.output = append(c.output, rp+" set action decrypt-except-certpinned")
		c.output = append(c.output, fmt.Sprintf("%s set decryption-profile %s", rp, profileName))

		c.Report.AddConverted(fmt.Sprintf("decryption-rule \"decrypt-%s\" for policy \"%s\" (deep-inspection -> decrypt-except-certpinned)", vname, pol.Name))
	}
}

// collectSSLExemptions gathers exempt categories and FQDN names for a given SSL profile.
func (c *VersaConverter) collectSSLExemptions(profileName string) (cats, fqdns []string) {
	prof, ok := c.parser.SSLSSHProfiles[profileName]
	if !ok {
		return
	}

	catSet := make(map[string]bool)

	// From ssl-exempt-categories (inline category IDs)
	for _, catID := range prof.ExemptCats {
		versaSlug, ok := FGCategoryToVersa[catID]
		if !ok {
			c.Report.AddWarning(fmt.Sprintf("SSL profile \"%s\": exempt category ID %d has no Versa mapping", profileName, catID))
			continue
		}
		if !catSet[versaSlug] {
			catSet[versaSlug] = true
			cats = append(cats, versaSlug)
		}
	}

	// From config ssl-exempt block
	for _, ex := range prof.Exemptions {
		switch ex.Type {
		case "fortiguard-cat", "":
			if ex.FortiguardCategory > 0 {
				versaSlug, ok := FGCategoryToVersa[ex.FortiguardCategory]
				if !ok {
					c.Report.AddWarning(fmt.Sprintf("SSL profile \"%s\": exempt category ID %d has no Versa mapping", profileName, ex.FortiguardCategory))
					continue
				}
				if !catSet[versaSlug] {
					catSet[versaSlug] = true
					cats = append(cats, versaSlug)
				}
			}
		case "wildcard-fqdn":
			if ex.WildcardFQDN != "" {
				fqdns = append(fqdns, c.sanitizer.Sanitize(ex.WildcardFQDN))
			}
		}
	}
	return
}

// --- URL Category Match ---
func (c *VersaConverter) emitURLCategoryMatch(rp string, pol *PolicyObj) {
	if pol.WebfilterProfile == "" {
		return
	}
	// If we generated a custom url-filtering profile, no match needed
	if _, ok := c.urlFilterProfiles[pol.WebfilterProfile]; ok {
		return
	}
	// If mapped in security_profile_map, the enforce section handles it
	if spMap, ok := c.secProfileMap["webfilter-profile"]; ok {
		if _, ok := spMap[pol.WebfilterProfile]; ok {
			return
		}
	}
	// No mapping — use match url-category as fallback
	versaCats := c.getBlockedVersaCategories(pol.WebfilterProfile)
	if len(versaCats) > 0 {
		c.output = append(c.output, fmt.Sprintf("%s match url-category predefined [ %s ]", rp, strings.Join(versaCats, " ")))
		c.Report.AddWarning(fmt.Sprintf("Policy \"%s\": webfilter \"%s\" has no url-filtering mapping, using match url-category predefined [ %s ] as fallback",
			pol.Name, pol.WebfilterProfile, strings.Join(versaCats, " ")))
	}
}

func (c *VersaConverter) getBlockedVersaCategories(profileName string) []string {
	wf, ok := c.parser.WebfilterProfiles[profileName]
	if !ok {
		return nil
	}
	var versaCats []string
	for _, cat := range wf.Categories {
		if cat.Action == "block" {
			if cat.ID == 0 {
				return nil // category 0 = all, url-filtering profile handles it
			}
			if versaName, ok := FGCategoryToVersa[cat.ID]; ok {
				versaCats = append(versaCats, versaName)
			} else {
				c.Report.AddWarning(fmt.Sprintf("Webfilter \"%s\": FortiGate category ID %d has no Versa mapping — add to FORTIGATE_CATEGORY_TO_VERSA", profileName, cat.ID))
			}
		}
	}
	return versaCats
}

// --- Security Profiles ---
func (c *VersaConverter) emitSecurityProfiles(rp string, pol *PolicyObj) {
	spMap := c.secProfileMap

	// Antivirus
	if pol.AVProfile != "" {
		if avMap, ok := spMap["av-profile"]; ok {
			if versaName, ok := avMap[pol.AVProfile]; ok {
				c.output = append(c.output, fmt.Sprintf("%s set security-profile antivirus predefined-av-profile \"%s\"", rp, versaName))
			} else {
				c.Report.AddWarning(fmt.Sprintf("Policy \"%s\": av-profile \"%s\" - no mapping in security_profile_map", pol.Name, pol.AVProfile))
			}
		} else {
			c.Report.AddWarning(fmt.Sprintf("Policy \"%s\": av-profile \"%s\" - no mapping in security_profile_map", pol.Name, pol.AVProfile))
		}
	}

	// DNS filtering
	if pol.DNSFilterProfile != "" {
		if dnsMap, ok := spMap["dnsfilter-profile"]; ok {
			if versaName, ok := dnsMap[pol.DNSFilterProfile]; ok {
				c.output = append(c.output, fmt.Sprintf("%s set security-profile dns-filtering predefined \"%s\"", rp, versaName))
			} else {
				c.Report.AddWarning(fmt.Sprintf("Policy \"%s\": dnsfilter-profile \"%s\" - no mapping in security_profile_map", pol.Name, pol.DNSFilterProfile))
			}
		} else {
			c.Report.AddWarning(fmt.Sprintf("Policy \"%s\": dnsfilter-profile \"%s\" - no mapping in security_profile_map", pol.Name, pol.DNSFilterProfile))
		}
	}

	// IPS
	if pol.IPSSensor != "" {
		if ipsMap, ok := spMap["ips-sensor"]; ok {
			if versaName, ok := ipsMap[pol.IPSSensor]; ok {
				c.output = append(c.output, fmt.Sprintf("%s set security-profile ips predefined-ips-profile \"%s\"", rp, versaName))
			} else {
				c.Report.AddWarning(fmt.Sprintf("Policy \"%s\": ips-sensor \"%s\" - no mapping in security_profile_map", pol.Name, pol.IPSSensor))
			}
		} else {
			c.Report.AddWarning(fmt.Sprintf("Policy \"%s\": ips-sensor \"%s\" - no mapping in security_profile_map", pol.Name, pol.IPSSensor))
		}
	}

	// URL filtering
	if pol.WebfilterProfile != "" {
		if profileName, ok := c.urlFilterProfiles[pol.WebfilterProfile]; ok {
			// Use generated custom profile
			c.output = append(c.output, fmt.Sprintf("%s set security-profile url-filtering user-defined %s", rp, profileName))
		} else if wfMap, ok := spMap["webfilter-profile"]; ok {
			if versaName, ok := wfMap[pol.WebfilterProfile]; ok {
				c.output = append(c.output, fmt.Sprintf("%s set security-profile url-filtering predefined %s", rp, versaName))
			} else {
				c.Report.AddWarning(fmt.Sprintf("Policy \"%s\": webfilter-profile \"%s\" - no mapping in security_profile_map", pol.Name, pol.WebfilterProfile))
			}
		} else {
			c.Report.AddWarning(fmt.Sprintf("Policy \"%s\": webfilter-profile \"%s\" - no mapping in security_profile_map", pol.Name, pol.WebfilterProfile))
		}
	}

	// Application list
	if pol.ApplicationList != "" {
		c.emitAppControl(rp, pol)
	}
}

// --- Application Control ---
func (c *VersaConverter) emitAppControl(rp string, pol *PolicyObj) {
	appProfile, ok := c.parser.AppListProfiles[pol.ApplicationList]
	if !ok {
		c.Report.AddWarning(fmt.Sprintf("Policy \"%s\": application-list \"%s\" not found in parsed config", pol.Name, pol.ApplicationList))
		return
	}

	var filterList []string
	var appList []string

	for _, entry := range appProfile.Entries {
		if entry.Action != "block" {
			continue
		}
		// Category-based entries → Versa application filters
		for _, catID := range entry.Category {
			if versaFilter, ok := FGAppCategoryToVersa[catID]; ok {
				filterList = append(filterList, versaFilter)
			} else {
				c.Report.AddWarning(fmt.Sprintf("Policy \"%s\": application category %d has no Versa mapping", pol.Name, catID))
			}
		}
		// Specific application entries → Versa predefined applications
		if entry.Application > 0 {
			if versaApp, ok := FGAppIDToVersa[entry.Application]; ok {
				appList = append(appList, versaApp)
			} else {
				c.Report.AddWarning(fmt.Sprintf("Policy \"%s\": application ID %d has no Versa mapping — add to FGAppIDToVersa", pol.Name, entry.Application))
			}
		}
	}

	filterList = dedup(filterList)
	appList = dedup(appList)

	if len(filterList) > 0 {
		c.output = append(c.output, fmt.Sprintf("%s match application predefined-filter-list [ %s ]", rp, strings.Join(filterList, " ")))
	}
	if len(appList) > 0 {
		c.output = append(c.output, fmt.Sprintf("%s match application predefined-application-list [ %s ]", rp, strings.Join(appList, " ")))
	}

	if len(filterList) == 0 && len(appList) == 0 {
		c.Report.AddWarning(fmt.Sprintf("Policy \"%s\": application-list \"%s\" has no block entries that could be mapped", pol.Name, pol.ApplicationList))
	} else {
		c.Report.AddConverted(fmt.Sprintf("application-list \"%s\" -> %d filters, %d apps", pol.ApplicationList, len(filterList), len(appList)))
	}
}

// --- Address Match ---
func (c *VersaConverter) emitAddrMatch(rp, direction string, addrs []string) {
	if len(addrs) == 0 || (len(addrs) == 1 && strings.EqualFold(addrs[0], "all")) {
		return
	}

	var addrList, groupList, countryList []string
	for _, a := range addrs {
		// Skip match-all addresses (0.0.0.0/0)
		if c.matchAllAddrs[a] {
			continue
		}
		if _, ok := c.parser.AddrGroups[a]; ok {
			groupList = append(groupList, c.sanitizer.Sanitize(a))
		} else if _, ok := c.rangeGroups[a]; ok {
			groupList = append(groupList, c.rangeGroups[a])
		} else if obj, ok := c.parser.Addresses[a]; ok {
			if obj.Type == "geography" {
				countryList = append(countryList, obj.Country)
				continue
			}
			addrList = append(addrList, c.sanitizer.Sanitize(a))
		} else if _, ok := c.parser.WildcardFQDNs[a]; ok {
			addrList = append(addrList, c.sanitizer.Sanitize(a))
		} else {
			addrList = append(addrList, c.sanitizer.Sanitize(a))
		}
	}

	if len(addrList) > 0 {
		c.output = append(c.output, fmt.Sprintf("%s match %s address address-list [ %s ]", rp, direction, strings.Join(addrList, " ")))
	}
	if len(groupList) > 0 {
		c.output = append(c.output, fmt.Sprintf("%s match %s address address-group-list [ %s ]", rp, direction, strings.Join(groupList, " ")))
	}
	if len(countryList) > 0 {
		c.output = append(c.output, fmt.Sprintf("%s match %s region [ %s ]", rp, direction, strings.Join(countryList, " ")))
	}
}

// isMatchAllService returns true if the service list contains ALL or an IP-protocol service.
func (c *VersaConverter) isMatchAllService(services []string) bool {
	for _, s := range services {
		if strings.EqualFold(s, "ALL") || c.matchAllSvcs[s] {
			return true
		}
	}
	return false
}

// resolvePolicyServices separates a policy's services into custom and predefined lists.
func (c *VersaConverter) resolvePolicyServices(pol *PolicyObj) (custom, predefined []string) {
	for _, s := range pol.Service {
		c.resolveSvcLeaves(s, &custom, &predefined)
	}
	custom = dedup(custom)
	predefined = dedup(predefined)
	return
}

// resolveSvcLeaves recursively resolves a service name to custom and/or predefined entries.
func (c *VersaConverter) resolveSvcLeaves(name string, custom, predefined *[]string) {
	// Check predefined mapping (covers both parsed and FG built-in services)
	if pre, ok := c.versaPredefined[name]; ok {
		*predefined = append(*predefined, pre)
		return
	}
	// Also check FGServiceToVersaPredefined for services not in parser.Services
	// (FortiGate built-in services that weren't in "config firewall service custom")
	if pre, ok := FGServiceToVersaPredefined[name]; ok {
		*predefined = append(*predefined, pre)
		return
	}
	// Check custom service
	if vs, ok := c.versaServices[name]; ok {
		*custom = append(*custom, vs...)
		return
	}
	// Check service group — flatten recursively
	if grp, ok := c.parser.SvcGroups[name]; ok {
		for _, m := range grp.Members {
			c.resolveSvcLeaves(m, custom, predefined)
		}
		return
	}
	// Fallback — treat as custom service name
	*custom = append(*custom, c.sanitizer.Sanitize(name))
}

func contains(sl []string, s string) bool {
	for _, v := range sl {
		if v == s {
			return true
		}
	}
	return false
}
