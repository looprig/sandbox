//go:build windows

package windows

import (
	"encoding/binary"
	"slices"
	"testing"

	win "golang.org/x/sys/windows"
)

func TestParseFileIDBothDirectoryInfo(t *testing.T) {
	buffer := append(directoryInfoRecord(t, ".", true), directoryInfoRecord(t, "Beta.txt", true)...)
	buffer = append(buffer, directoryInfoRecord(t, "alpha", false)...)
	names, err := parseFileIDBothDirectoryInfo(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(names, []string{"Beta.txt", "alpha"}) {
		t.Fatalf("names = %q", names)
	}
}

func TestParseFileIDBothDirectoryInfoRejectsMalformedRecords(t *testing.T) {
	for name, mutate := range map[string]func([]byte){
		"odd name bytes": func(record []byte) { binary.LittleEndian.PutUint32(record[60:64], 3) },
		"short next":     func(record []byte) { binary.LittleEndian.PutUint32(record[0:4], 8) },
		"unaligned next": func(record []byte) { binary.LittleEndian.PutUint32(record[0:4], 105) },
		"unsafe name": func(record []byte) {
			copy(record[fileIDBothDirectoryInfoHeaderSize:], []byte{'/', 0})
		},
	} {
		t.Run(name, func(t *testing.T) {
			record := directoryInfoRecord(t, "x", false)
			mutate(record)
			if _, err := parseFileIDBothDirectoryInfo(record); err == nil {
				t.Fatal("malformed directory record accepted")
			}
		})
	}
}

func directoryInfoRecord(t *testing.T, name string, hasNext bool) []byte {
	t.Helper()
	units, err := win.UTF16FromString(name)
	if err != nil {
		t.Fatal(err)
	}
	units = units[:len(units)-1]
	size := fileIDBothDirectoryInfoHeaderSize + len(units)*2
	if hasNext {
		size = (size + 7) &^ 7
	}
	record := make([]byte, size)
	if hasNext {
		binary.LittleEndian.PutUint32(record[0:4], uint32(size))
	}
	binary.LittleEndian.PutUint32(record[60:64], uint32(len(units)*2))
	for index, unit := range units {
		binary.LittleEndian.PutUint16(record[fileIDBothDirectoryInfoHeaderSize+index*2:], unit)
	}
	return record
}
