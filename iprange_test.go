package forti2versa

import (
	"net/netip"
	"testing"
)

func TestSummarizeRangeSingle(t *testing.T) {
	start := netip.MustParseAddr("10.0.0.0")
	end := netip.MustParseAddr("10.0.0.255")
	cidrs := summarizeRange(start, end)
	if len(cidrs) != 1 {
		t.Fatalf("expected 1 CIDR, got %d: %v", len(cidrs), cidrs)
	}
	if cidrs[0].String() != "10.0.0.0/24" {
		t.Errorf("got %s, want 10.0.0.0/24", cidrs[0])
	}
}

func TestSummarizeRangeMultiple(t *testing.T) {
	// IP_Range_Finance: 10.10.40.100 - 10.10.40.200 → 6 CIDRs
	start := netip.MustParseAddr("10.10.40.100")
	end := netip.MustParseAddr("10.10.40.200")
	cidrs := summarizeRange(start, end)
	if len(cidrs) != 6 {
		t.Errorf("expected 6 CIDRs for finance range, got %d: %v", len(cidrs), cidrs)
	}
}

func TestSummarizeRangeLarge(t *testing.T) {
	// Internal_Networks: 10.0.0.1 - 10.255.255.254 → 46 CIDRs
	start := netip.MustParseAddr("10.0.0.1")
	end := netip.MustParseAddr("10.255.255.254")
	cidrs := summarizeRange(start, end)
	if len(cidrs) != 46 {
		t.Errorf("expected 46 CIDRs for internal networks, got %d", len(cidrs))
	}
}

func TestSummarizeRangeExact(t *testing.T) {
	// Single IP
	start := netip.MustParseAddr("1.2.3.4")
	end := netip.MustParseAddr("1.2.3.4")
	cidrs := summarizeRange(start, end)
	if len(cidrs) != 1 {
		t.Fatalf("expected 1 CIDR, got %d", len(cidrs))
	}
	if cidrs[0].String() != "1.2.3.4/32" {
		t.Errorf("got %s, want 1.2.3.4/32", cidrs[0])
	}
}
