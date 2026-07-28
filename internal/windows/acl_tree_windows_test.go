//go:build windows

package windows

import (
	"encoding/binary"
	"slices"
	"testing"

	win "golang.org/x/sys/windows"
)

func TestParseFileIDBothDirectoryInfo(t *testing.T) {
	dot := directoryInfoRecord(t, ".", true)
	beta := directoryInfoRecord(t, "Beta.txt", true)
	binary.LittleEndian.PutUint32(beta[56:60], win.FILE_ATTRIBUTE_DIRECTORY)
	alpha := directoryInfoRecord(t, "alpha", false)
	binary.LittleEndian.PutUint32(alpha[56:60], win.FILE_ATTRIBUTE_REPARSE_POINT)
	buffer := append(dot, beta...)
	buffer = append(buffer, alpha...)
	entries, err := parseFileIDBothDirectoryInfo(buffer)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, len(entries))
	for index := range entries {
		names[index] = entries[index].name
	}
	if !slices.Equal(names, []string{"Beta.txt", "alpha"}) {
		t.Fatalf("names = %q", names)
	}
	if !entries[0].directory || entries[0].reparse || entries[1].directory || !entries[1].reparse {
		t.Fatalf("entry types = %+v, want directory then reparse", entries)
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
