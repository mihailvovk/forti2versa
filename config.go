package forti2versa

// Config holds converter configuration loaded from JSON.
type Config struct {
	TemplateName       string                       `json:"template_name"`
	OrgName            string                       `json:"org_name"`
	PolicyName         string                       `json:"policy_name"`
	InterfaceZoneMap   map[string]string            `json:"interface_zone_map"`
	SkipOrphans        bool                         `json:"skip_orphans"`
	ScheduleMap        map[string]string            `json:"schedule_map"`
	SecurityProfileMap map[string]map[string]string `json:"security_profile_map"`
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		TemplateName: "<TEMPLATE-NAME>",
		OrgName:      "<ORG>",
		PolicyName:   "Default-Policy",
		SkipOrphans:  true,
	}
}

// EnsureMaps initializes nil maps to empty maps.
func (c *Config) EnsureMaps() {
	if c.InterfaceZoneMap == nil {
		c.InterfaceZoneMap = make(map[string]string)
	}
	if c.ScheduleMap == nil {
		c.ScheduleMap = make(map[string]string)
	}
	if c.SecurityProfileMap == nil {
		c.SecurityProfileMap = make(map[string]map[string]string)
	}
}
