package forti2versa

// FortiGate data model types parsed from config text.

type AddressObj struct {
	Name    string
	Type    string // ipmask, fqdn, iprange, geography
	Subnet  string // "10.0.0.0 255.255.255.0"
	FQDN    string
	StartIP string
	EndIP   string
	Country string
	Comment string
}

type AddrGroup struct {
	Name    string
	Members []string
	Comment string
}

type ServiceObj struct {
	Name         string
	Protocol     string // "TCP", "UDP", "TCP UDP", "IP"
	TCPPortRange string // "80", "25 587", "8080:1024-65535"
	UDPPortRange string
	Comment      string
}

type SvcGroup struct {
	Name    string
	Members []string
	Comment string
}

type WebfilterCategory struct {
	ID     int
	Action string // block, monitor, warning, allow, exempt
}

type WebfilterProfile struct {
	Name           string
	Comment        string
	Categories     []WebfilterCategory
	URLFilterTable int
}

type AppListEntry struct {
	Category    []int  // category IDs (can be multiple per entry)
	Application int    // specific application ID (0 if none)
	Action      string // block, monitor, pass
}

type AppListProfile struct {
	Name                  string
	Comment               string
	Entries               []AppListEntry
	UnknownApplicationAction string // block, pass
}

type WildcardFQDN struct {
	Name         string
	WildcardFQDN string // "*.adobe.com"
}

type SSLExemption struct {
	FortiguardCategory int
	Type               string // "fortiguard-cat", "wildcard-fqdn"
	WildcardFQDN       string // reference to wildcard-fqdn object name
}

type SSLProtocol struct {
	Name   string // "https", "ftps", "imaps", "smtps", "pop3s"
	Ports  []int  // e.g. [443], [990], [993]
	Status string // "deep-inspection", "certificate-inspection"
}

type SSLSSHProfile struct {
	Name       string
	Protocols  []SSLProtocol  // parsed from config https/ftps/imaps/etc sub-blocks
	ExemptCats []int          // from "set ssl-exempt-categories"
	Exemptions []SSLExemption // from "config ssl-exempt" block
}

type DNSFilterCategory struct {
	ID     int
	Action string // "block", "monitor", "allow"
}

type DNSFilterObj struct {
	Name       string
	Categories []DNSFilterCategory
}

type URLFilterEntry struct {
	URL    string
	Type   string // "wildcard", "simple", "regex"
	Action string // "block", "monitor", "exempt", "allow"
}

type URLFilterTable struct {
	ID      int
	Name    string
	Entries []URLFilterEntry
}

type OnetimeSchedule struct {
	Name  string
	Start string // "00:01 2019/10/11"
	End   string // "23:59 2019/10/28"
}

// AVProfile represents a FortiGate antivirus profile with enabled protocol sub-blocks.
type AVProfile struct {
	Name      string
	Protocols []string // "http", "ftp", "smtp", "imap", "pop3"
}

type PolicyObj struct {
	ID               int
	Name             string
	SrcIntf          string
	DstIntf          string
	SrcAddr          []string
	DstAddr          []string
	Action           string // accept, deny
	Schedule         string
	Service          []string
	Groups           []string
	Users            []string
	LogTraffic       string
	NAT              string
	Comments         string
	UTMStatus        string
	WebfilterProfile string
	AVProfile        string
	IPSSensor        string
	ApplicationList  string
	DNSFilterProfile string
	SSLSSHProfile    string
	TrafficShaper    string
}
