package forti2versa

import (
	"regexp"
	"strings"
)

var (
	reInvisible  = regexp.MustCompile("[\u00a0\u200b\u200c\u200d\ufeff\u2060\u202f\u2007\u2009\u200a]")
	reIllegal    = regexp.MustCompile(`[^A-Za-z0-9_-]`)
	reMultiUnder = regexp.MustCompile(`_{2,}`)
)

// NameSanitizer sanitizes names to Versa-legal characters [A-Za-z0-9_-], max 63 chars.
type NameSanitizer struct {
	nameMap map[string]string // original -> sanitized
	used    map[string]string // sanitized -> original (first owner)
}

func NewNameSanitizer() *NameSanitizer {
	return &NameSanitizer{
		nameMap: make(map[string]string),
		used:    make(map[string]string),
	}
}

func (s *NameSanitizer) Sanitize(name string) string {
	if v, ok := s.nameMap[name]; ok {
		return v
	}
	cleaned := reInvisible.ReplaceAllString(name, "")
	cleaned = reIllegal.ReplaceAllString(cleaned, "_")
	cleaned = reMultiUnder.ReplaceAllString(cleaned, "_")
	cleaned = strings.Trim(cleaned, "_")
	if cleaned == "" {
		cleaned = "unnamed"
	}
	if len(cleaned) > 63 {
		cleaned = cleaned[:63]
	}
	// Handle collisions
	final := cleaned
	suffix := 2
	for {
		owner, exists := s.used[final]
		if !exists || owner == name {
			break
		}
		tag := "-" + itoa(suffix)
		cutLen := 63 - len(tag)
		if cutLen > len(cleaned) {
			cutLen = len(cleaned)
		}
		final = cleaned[:cutLen] + tag
		suffix++
	}
	s.nameMap[name] = final
	s.used[final] = name
	return final
}

func (s *NameSanitizer) WasRenamed(original string) bool {
	v, ok := s.nameMap[original]
	return ok && v != original
}

// itoa converts int to string without importing strconv in this file.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
