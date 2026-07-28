package baseline

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"testing"
)

func TestInspectTLSFixtureRejectsMalformedBounds(t *testing.T) {
	image, err := GenerateTLSFixture("amd64")
	if err != nil {
		t.Fatal(err)
	}
	badVA := append([]byte(nil), image...)
	rdataRaw := int(peHeadersSize + peSectionSize)
	binary.LittleEndian.PutUint64(badVA[rdataRaw+int(peTLSDirectoryOff)+24:], ^uint64(0))
	for _, data := range [][]byte{image[:200], badVA} {
		file, err := pe.NewFile(bytes.NewReader(data))
		if err == nil {
			_, err = InspectTLSFixture(file)
			file.Close()
		}
		if err == nil {
			t.Fatal("malformed PE unexpectedly accepted")
		}
	}
}

func FuzzInspectTLSFixtureDoesNotPanic(f *testing.F) {
	for _, arch := range []string{"amd64", "arm64"} {
		image, _ := GenerateTLSFixture(arch)
		f.Add(image)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		file, err := pe.NewFile(bytes.NewReader(data))
		if err != nil {
			return
		}
		defer file.Close()
		_, _ = InspectTLSFixture(file)
	})
}
