//go:build windows

package windows

import (
	"encoding/binary"
	"testing"
)

func TestWindowsTCPPortOwnerCombinesIPv4AndIPv6Safely(t *testing.T) {
	tables := fakeTCPOwnerTables{tables: map[uint32][]byte{
		addressFamilyIPv4: encodeTCPOwnerRows(addressFamilyIPv4, []tcpOwnerRow{{state: tcpStateListen, port: 9001, pid: 42}}),
		addressFamilyIPv6: encodeTCPOwnerRows(addressFamilyIPv6, []tcpOwnerRow{{state: tcpStateListen, port: 9002, pid: 43}}),
	}}
	owner := windowsTCPPortOwner{tables: tables}
	if pid, owned, err := owner.OwnerPID(9001); err != nil || !owned || pid != 42 {
		t.Fatalf("port 9001 = pid %d, owned %v, err %v", pid, owned, err)
	}
	if pid, owned, err := owner.OwnerPID(9003); err != nil || owned || pid != 0 {
		t.Fatalf("port 9003 = pid %d, owned %v, err %v", pid, owned, err)
	}
	// Multiple listeners make PID attribution ambiguous, but ownership remains
	// fail-closed and is reported with PID zero.
	tables.tables[addressFamilyIPv6] = encodeTCPOwnerRows(addressFamilyIPv6, []tcpOwnerRow{{state: tcpStateListen, port: 9001, pid: 99}})
	if pid, owned, err := owner.OwnerPID(9001); err != nil || !owned || pid != 0 {
		t.Fatalf("ambiguous port = pid %d, owned %v, err %v", pid, owned, err)
	}
}

func TestParseTCPOwnerRowsRejectsTruncation(t *testing.T) {
	data := encodeTCPOwnerRows(addressFamilyIPv4, []tcpOwnerRow{{state: tcpStateListen, port: 9001, pid: 42}})
	if _, err := parseTCPOwnerRows(data[:len(data)-1], addressFamilyIPv4); err == nil {
		t.Fatal("truncated owner table accepted")
	}
}

type fakeTCPOwnerTables struct{ tables map[uint32][]byte }

func (t fakeTCPOwnerTables) Table(family uint32) ([]byte, error) { return t.tables[family], nil }

func encodeTCPOwnerRows(family uint32, rows []tcpOwnerRow) []byte {
	rowSize, stateOffset, portOffset, pidOffset := 24, 0, 8, 20
	if family == addressFamilyIPv6 {
		rowSize, stateOffset, portOffset, pidOffset = 56, 48, 20, 52
	}
	data := make([]byte, 4+rowSize*len(rows))
	binary.LittleEndian.PutUint32(data, uint32(len(rows)))
	for index, value := range rows {
		row := data[4+index*rowSize : 4+(index+1)*rowSize]
		binary.LittleEndian.PutUint32(row[stateOffset:], value.state)
		binary.BigEndian.PutUint16(row[portOffset:], value.port)
		binary.LittleEndian.PutUint32(row[pidOffset:], value.pid)
	}
	return data
}
