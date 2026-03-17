package forti2versa

import "testing"

func TestSanitizeBasic(t *testing.T) {
	s := NewNameSanitizer()
	tests := []struct {
		input, want string
	}{
		{"simple-name", "simple-name"},
		{"already_ok_123", "already_ok_123"},
		{"HR & Payroll Servers", "HR_Payroll_Servers"},
		{"Server.Farm.Production", "Server_Farm_Production"},
		{"DMZ-Servers(Primary)", "DMZ-Servers_Primary"},
		{"Branch@Office-LAN", "Branch_Office-LAN"},
		{"DC_Rostock/Standby", "DC_Rostock_Standby"},
		{"Backup#Servers-Orphan", "Backup_Servers-Orphan"},
		{"Finance+Controllers", "Finance_Controllers"},
		{"Mgmt:Network-Orphan", "Mgmt_Network-Orphan"},
	}
	for _, tt := range tests {
		got := s.Sanitize(tt.input)
		if got != tt.want {
			t.Errorf("Sanitize(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestSanitizeTruncation(t *testing.T) {
	s := NewNameSanitizer()
	long := "RAVPN-PRE_VeryLongPolicyNameThatDefinitelyExceedsTheVersa63CharacterLimitForFirewallRuleNaming"
	got := s.Sanitize(long)
	if len(got) > 63 {
		t.Errorf("Sanitize produced name longer than 63 chars: %d", len(got))
	}
	want := "RAVPN-PRE_VeryLongPolicyNameThatDefinitelyExceedsTheVersa63Char"
	if got != want {
		t.Errorf("Sanitize(%q) = %q, want %q", long, got, want)
	}
}

func TestSanitizeInvisible(t *testing.T) {
	s := NewNameSanitizer()
	// Zero-width space in name
	got := s.Sanitize("test\u200bname")
	if got != "testname" {
		t.Errorf("Sanitize with ZWSP = %q, want %q", got, "testname")
	}
}

func TestSanitizeCollision(t *testing.T) {
	s := NewNameSanitizer()
	// Two different names that sanitize to the same thing
	a := s.Sanitize("foo.bar")
	b := s.Sanitize("foo/bar")
	if a == b {
		t.Errorf("collision not handled: %q and %q both got %q", "foo.bar", "foo/bar", a)
	}
	if a != "foo_bar" {
		t.Errorf("first: got %q, want %q", a, "foo_bar")
	}
	if b != "foo_bar-2" {
		t.Errorf("second: got %q, want %q", b, "foo_bar-2")
	}
}

func TestSanitizeEmpty(t *testing.T) {
	s := NewNameSanitizer()
	got := s.Sanitize("...")
	if got != "unnamed" {
		t.Errorf("Sanitize('...') = %q, want 'unnamed'", got)
	}
}

func TestWasRenamed(t *testing.T) {
	s := NewNameSanitizer()
	s.Sanitize("simple-name")
	s.Sanitize("has.dot")
	if s.WasRenamed("simple-name") {
		t.Error("simple-name should not be renamed")
	}
	if !s.WasRenamed("has.dot") {
		t.Error("has.dot should be renamed")
	}
}
