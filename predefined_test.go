package forti2versa

import "testing"

func TestCatmapVersaSlugsValid(t *testing.T) {
	for fgID, versaSlug := range FGCategoryToVersa {
		if !VersaURLCategories[versaSlug] {
			t.Errorf("FGCategoryToVersa[%d] = %q is not a valid Versa predefined URL category", fgID, versaSlug)
		}
	}
}

func TestAppCategoryMappingsValid(t *testing.T) {
	for fgCat, versaFilter := range FGAppCategoryToVersa {
		if !VersaAppFilters[versaFilter] {
			t.Errorf("FGAppCategoryToVersa[%d] = %q is not a valid Versa predefined application filter", fgCat, versaFilter)
		}
	}
}

func TestFGServiceMappingsValid(t *testing.T) {
	for fgName, versaSlug := range FGServiceToVersaPredefined {
		if !VersaPredefinedServices[versaSlug] {
			t.Errorf("FGServiceToVersaPredefined[%s] = %q is not a valid Versa predefined service", fgName, versaSlug)
		}
	}
}

func TestPredefinedProfileMaps(t *testing.T) {
	// Verify the test config uses valid profile names
	cfg := newTestConfig()
	for section, profiles := range cfg.SecurityProfileMap {
		validators := map[string]map[string]bool{
			"av-profile":        VersaAVProfiles,
			"ips-sensor":        VersaIPSProfiles,
			"webfilter-profile": VersaURLFilteringProfiles,
			"dnsfilter-profile": VersaDNSFilteringProfiles,
		}
		valid, ok := validators[section]
		if !ok {
			continue
		}
		for fgName, versaName := range profiles {
			if !valid[versaName] {
				t.Errorf("SecurityProfileMap[%s][%s] = %q is not a valid Versa predefined profile", section, fgName, versaName)
			}
		}
	}
}
