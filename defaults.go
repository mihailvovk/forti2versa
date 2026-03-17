package forti2versa

import (
	"math/rand"
	"strings"
	"time"
)

var templateAdjectives = []string{
	"STEADY", "SWIFT", "BRIGHT", "CLEAR", "NOBLE", "SILENT", "GOLDEN", "CORAL",
	"ARCTIC", "ALPINE", "IRON", "CEDAR", "STORM", "FROST", "RIVER", "SHADOW",
	"CRIMSON", "SILVER", "AZURE", "EMBER", "GRANITE", "CRYSTAL", "MARBLE", "COBALT",
	"SUMMIT", "FALCON", "HARBOR", "RIDGE", "MEADOW", "TIMBER",
}

var templateNouns = []string{
	"FALCON", "BRIDGE", "TOWER", "SHIELD", "HARBOR", "SUMMIT", "ANCHOR", "BEACON",
	"CIPHER", "PRISM", "FORGE", "BASTION", "SENTINEL", "RAMPART", "PINNACLE", "CONDUIT",
	"KEYSTONE", "GATEWAY", "VANGUARD", "FRONTIER", "NEXUS", "VERTEX", "MATRIX", "AEGIS",
	"TEMPEST", "MONARCH", "PHOENIX", "COMPASS", "MERIDIAN", "VENTURE",
}

// GenerateTemplateName returns a random two-word template name like "STEADY-FALCON".
func GenerateTemplateName() string {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	adj := templateAdjectives[r.Intn(len(templateAdjectives))]
	noun := templateNouns[r.Intn(len(templateNouns))]
	return adj + "-" + noun
}

var orgPrefixes = []string{
	"NORTH", "SOUTH", "EAST", "WEST", "CENTRAL", "PACIFIC", "ATLANTIC",
	"ALPINE", "COASTAL", "METRO", "DELTA", "SUMMIT", "GLOBAL", "PRIME",
}

var orgSuffixes = []string{
	"NET", "SYSTEMS", "LINK", "CONNECT", "EDGE", "CORE", "GROUP",
	"TECH", "OPS", "GRID", "HUB", "BASE", "WORKS", "CLOUD",
}

// GenerateOrgName returns a random org name like "NORTH-NET".
func GenerateOrgName() string {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	prefix := orgPrefixes[r.Intn(len(orgPrefixes))]
	suffix := orgSuffixes[r.Intn(len(orgSuffixes))]
	return prefix + "-" + suffix
}

// zoneExactMap maps exact FortiGate interface names to Versa zone names.
var zoneExactMap = map[string]string{
	"wan1":       "Intf-Internet-Zone",
	"wan2":       "Intf-Internet-2-Zone",
	"port1":      "Intf-LAN-Zone",
	"port2":      "Intf-LAN-2-Zone",
	"port3":      "Intf-LAN-3-Zone",
	"dmz":        "Intf-DMZ-Zone",
	"ssl.root":   "RAVPN-Zone",
	"internal":   "Intf-Internal-Zone",
	"guest-vlan": "Intf-Guest-Zone",
	"loopback":   "Intf-Mgmt-Zone",
	"ha":         "Intf-HA-Zone",
	"modem":      "Intf-Modem-Zone",
}

// SuggestZoneMap takes a list of FortiGate interface names and returns a
// suggested mapping to Versa zone names using exact matches and pattern-based fallbacks.
func SuggestZoneMap(interfaces []string) map[string]string {
	result := make(map[string]string, len(interfaces))
	for _, intf := range interfaces {
		result[intf] = suggestZone(intf)
	}
	return result
}

func suggestZone(intf string) string {
	// Exact match first
	if zone, ok := zoneExactMap[intf]; ok {
		return zone
	}

	lower := strings.ToLower(intf)

	// Pattern-based fallbacks
	if strings.HasPrefix(lower, "wan") {
		return "Intf-Internet-" + sanitizeZonePart(intf[3:]) + "-Zone"
	}
	if strings.HasPrefix(lower, "port") {
		return "Intf-LAN-" + sanitizeZonePart(intf[4:]) + "-Zone"
	}
	if strings.HasPrefix(lower, "vlan") {
		return "Intf-VLAN-" + sanitizeZonePart(intf[4:]) + "-Zone"
	}
	if strings.HasPrefix(lower, "tunnel") {
		return "Intf-Tunnel-" + sanitizeZonePart(intf[6:]) + "-Zone"
	}
	if strings.Contains(lower, "dmz") {
		return "Intf-DMZ-Zone"
	}
	if strings.Contains(lower, "guest") {
		return "Intf-Guest-Zone"
	}
	if strings.Contains(lower, "mgmt") {
		return "Intf-Mgmt-Zone"
	}
	if strings.Contains(lower, "internal") {
		return "Intf-Internal-Zone"
	}

	// Fallback: Intf-<SANITIZED>-Zone
	sanitized := reIllegal.ReplaceAllString(intf, "-")
	sanitized = strings.Trim(sanitized, "-")
	if sanitized == "" {
		sanitized = "Unknown"
	}
	return "Intf-" + strings.ToUpper(sanitized[:1]) + sanitized[1:] + "-Zone"
}

func sanitizeZonePart(s string) string {
	s = strings.TrimLeft(s, "-_.")
	if s == "" {
		return "1"
	}
	return s
}
