package forti2versa

import (
	"encoding/binary"
	"math/bits"
	"net/netip"
)

// summarizeRange returns the minimal set of CIDR prefixes covering [start, end].
// Equivalent to Python's ipaddress.summarize_address_range().
func summarizeRange(start, end netip.Addr) []netip.Prefix {
	if !start.Is4() || !end.Is4() {
		return nil
	}
	sa4 := start.As4()
	ea4 := end.As4()
	s := binary.BigEndian.Uint32(sa4[:])
	e := binary.BigEndian.Uint32(ea4[:])
	if s > e {
		return nil
	}
	var result []netip.Prefix
	for s <= e {
		// max prefix length (most specific) is number of trailing zeros
		trailingZeros := bits.TrailingZeros32(s)
		if s == 0 {
			trailingZeros = 32
		}
		prefixLen := 32 - trailingZeros

		// shrink prefix until it doesn't overshoot end
		for prefixLen > 0 {
			// network size = 1 << (32 - prefixLen)
			size := uint64(1) << (32 - prefixLen)
			last := uint64(s) + size - 1
			if last <= uint64(e) {
				break
			}
			prefixLen++
		}
		if prefixLen == 0 {
			size := uint64(1) << 32
			last := uint64(s) + size - 1
			if last > uint64(e) {
				prefixLen = 1
			}
		}

		var addr [4]byte
		binary.BigEndian.PutUint32(addr[:], s)
		prefix := netip.PrefixFrom(netip.AddrFrom4(addr), prefixLen)
		result = append(result, prefix)

		// advance past this prefix
		size := uint64(1) << (32 - prefixLen)
		next := uint64(s) + size
		if next > uint64(0xFFFFFFFF) {
			break
		}
		s = uint32(next)
	}
	return result
}
