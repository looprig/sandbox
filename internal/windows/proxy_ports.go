package windows

import "slices"

// foreignProxyPortOwners drops every pinned proxy port whose listening
// process is self. ReserveEgressProxy binds all of the installation's pinned
// ports in the host process itself (the proxy and its guard listeners), so
// a later inspection from that same process finds them owned and, before
// this filter, reported its own reservation as a squatter: every Compile
// after the first reservation saw the installation as stale (review L8).
// A port owned by any other process still counts.
func foreignProxyPortOwners(owners map[uint16]uint32, self uint32) map[uint16]uint32 {
	var foreign map[uint16]uint32
	for port, pid := range owners {
		if pid == self && self != 0 {
			continue
		}
		if foreign == nil {
			foreign = make(map[uint16]uint32, len(owners))
		}
		foreign[port] = pid
	}
	return foreign
}

// sameProxyPortSet compares two proxy-port lists as sets. Both sides are
// already validated as small and duplicate-free (validateProxyPorts).
func sameProxyPortSet(left, right []uint16) bool {
	if len(left) != len(right) {
		return false
	}
	sortedLeft := slices.Clone(left)
	sortedRight := slices.Clone(right)
	slices.Sort(sortedLeft)
	slices.Sort(sortedRight)
	return slices.Equal(sortedLeft, sortedRight)
}
