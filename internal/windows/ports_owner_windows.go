//go:build windows

package windows

import (
	"encoding/binary"
	"errors"
	"fmt"
	"unsafe"

	win "golang.org/x/sys/windows"
)

const (
	addressFamilyIPv4        = 2
	addressFamilyIPv6        = 23
	tcpTableOwnerPIDListener = 3
	tcpStateListen           = 2
)

type tcpOwnerTableAPI interface {
	Table(addressFamily uint32) ([]byte, error)
}

type windowsTCPPortOwner struct{ tables tcpOwnerTableAPI }

func (o windowsTCPPortOwner) OwnerPID(port uint16) (uint32, bool, error) {
	if o.tables == nil || port == 0 {
		return 0, false, errors.New("sandbox: invalid Windows TCP owner lookup")
	}
	owners := make(map[uint32]struct{})
	owned := false
	for _, family := range []uint32{addressFamilyIPv4, addressFamilyIPv6} {
		table, err := o.tables.Table(family)
		if err != nil {
			return 0, false, fmt.Errorf("read Windows TCP owner table for family %d: %w", family, err)
		}
		rows, err := parseTCPOwnerRows(table, family)
		if err != nil {
			return 0, false, err
		}
		for _, row := range rows {
			if row.state == tcpStateListen && row.port == port {
				owned = true
				if row.pid != 0 {
					owners[row.pid] = struct{}{}
				}
			}
		}
	}
	if !owned {
		return 0, false, nil
	}
	if len(owners) != 1 {
		return 0, true, nil
	}
	for pid := range owners {
		return pid, true, nil
	}
	return 0, true, nil
}

type tcpOwnerRow struct {
	state uint32
	port  uint16
	pid   uint32
}

func parseTCPOwnerRows(table []byte, family uint32) ([]tcpOwnerRow, error) {
	if len(table) < 4 {
		return nil, errors.New("sandbox: truncated Windows TCP owner table")
	}
	count := int(binary.LittleEndian.Uint32(table[:4]))
	rowSize, stateOffset, portOffset, pidOffset := 0, 0, 0, 0
	switch family {
	case addressFamilyIPv4:
		rowSize, stateOffset, portOffset, pidOffset = 24, 0, 8, 20
	case addressFamilyIPv6:
		rowSize, stateOffset, portOffset, pidOffset = 56, 48, 20, 52
	default:
		return nil, errors.New("sandbox: unsupported Windows TCP owner address family")
	}
	if count < 0 || count > (len(table)-4)/rowSize || 4+count*rowSize != len(table) {
		return nil, errors.New("sandbox: malformed Windows TCP owner table length")
	}
	rows := make([]tcpOwnerRow, count)
	for index := range count {
		row := table[4+index*rowSize : 4+(index+1)*rowSize]
		rows[index] = tcpOwnerRow{
			state: binary.LittleEndian.Uint32(row[stateOffset:]),
			port:  binary.BigEndian.Uint16(row[portOffset : portOffset+2]),
			pid:   binary.LittleEndian.Uint32(row[pidOffset:]),
		}
	}
	return rows, nil
}

type ipHelperTCPTableAPI struct{}

var getExtendedTCPTable = win.NewLazySystemDLL("iphlpapi.dll").NewProc("GetExtendedTcpTable")

func (ipHelperTCPTableAPI) Table(addressFamily uint32) ([]byte, error) {
	var size uint32
	result, _, _ := getExtendedTCPTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, uintptr(addressFamily), tcpTableOwnerPIDListener, 0)
	if result != uintptr(win.ERROR_INSUFFICIENT_BUFFER) || size < 4 {
		if result == 0 && size == 0 {
			return []byte{0, 0, 0, 0}, nil
		}
		return nil, fmt.Errorf("size Windows TCP owner table: %w", syscallError(result))
	}
	buffer := make([]byte, size)
	result, _, _ = getExtendedTCPTable.Call(uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size)), 0, uintptr(addressFamily), tcpTableOwnerPIDListener, 0)
	if result != 0 {
		return nil, fmt.Errorf("read Windows TCP owner table: %w", syscallError(result))
	}
	if int(size) > len(buffer) {
		return nil, errors.New("sandbox: Windows TCP owner table size grew unexpectedly")
	}
	return buffer[:size], nil
}

func syscallError(code uintptr) error {
	if code == 0 {
		return nil
	}
	return win.Errno(code)
}
