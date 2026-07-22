package baseline

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	peImageBase       = uint64(0x400000)
	peTextRVA         = uint32(0x1000)
	peRDataRVA        = uint32(0x2000)
	peDataRVA         = uint32(0x3000)
	peSectionSize     = uint32(0x200)
	peHeadersSize     = uint32(0x400)
	peTLSDirectoryOff = uint32(0x180)
	peCallbackMsgOff  = uint32(0x1c0)
	peMainMsgOff      = uint32(0x1e0)
	peCallbackArray   = uint32(0x10)
	peWrittenOff      = uint32(0x20)
	peCallbackFlagOff = uint32(0x28)
	callbackMarker    = "TLS_CALLBACK_EXECUTED\n"
	mainMarker        = "MAIN_AFTER_TLS\n"
)

type TLSFixtureInfo struct {
	Machine        uint16
	EntryPointRVA  uint32
	CallbackVA     uint64
	CallbackMarker string
	MainMarker     string
}

func GenerateTLSFixture(arch string) ([]byte, error) {
	var machine uint16
	var text []byte
	var entryOff uint32
	var err error
	switch arch {
	case "amd64":
		machine = pe.IMAGE_FILE_MACHINE_AMD64
		text, entryOff, err = generateAMD64Text()
	case "arm64":
		machine = pe.IMAGE_FILE_MACHINE_ARM64
		text, entryOff, err = generateARM64Text()
	default:
		return nil, fmt.Errorf("unsupported TLS fixture architecture %q", arch)
	}
	if err != nil {
		return nil, err
	}
	if len(text) > int(peSectionSize) {
		return nil, fmt.Errorf("TLS fixture text is %d bytes, maximum %d", len(text), peSectionSize)
	}

	rdata := make([]byte, peSectionSize)
	data := make([]byte, peSectionSize)
	buildImports(rdata)
	binary.LittleEndian.PutUint64(rdata[peTLSDirectoryOff+0:], peImageBase+uint64(peDataRVA))
	binary.LittleEndian.PutUint64(rdata[peTLSDirectoryOff+8:], peImageBase+uint64(peDataRVA)+1)
	binary.LittleEndian.PutUint64(rdata[peTLSDirectoryOff+16:], peImageBase+uint64(peDataRVA)+8)
	binary.LittleEndian.PutUint64(rdata[peTLSDirectoryOff+24:], peImageBase+uint64(peDataRVA)+uint64(peCallbackArray))
	copy(rdata[peCallbackMsgOff:], callbackMarker)
	copy(rdata[peMainMsgOff:], mainMarker)
	binary.LittleEndian.PutUint64(data[peCallbackArray:], peImageBase+uint64(peTextRVA))

	image := make([]byte, peHeadersSize+3*peSectionSize)
	buildPEHeaders(image[:peHeadersSize], machine, peTextRVA+entryOff)
	copy(image[peHeadersSize:], text)
	copy(image[peHeadersSize+peSectionSize:], rdata)
	copy(image[peHeadersSize+2*peSectionSize:], data)
	return image, nil
}

func buildImports(rdata []byte) {
	const (
		intOff       = uint32(0x40)
		iatOff       = uint32(0x80)
		dllNameOff   = uint32(0xc0)
		exitNameOff  = uint32(0xe0)
		stdNameOff   = uint32(0xf0)
		writeNameOff = uint32(0x108)
	)
	put32 := func(off, value uint32) { binary.LittleEndian.PutUint32(rdata[off:], value) }
	put32(0, peRDataRVA+intOff)
	put32(12, peRDataRVA+dllNameOff)
	put32(16, peRDataRVA+iatOff)
	for index, nameOff := range []uint32{exitNameOff, stdNameOff, writeNameOff} {
		value := uint64(peRDataRVA + nameOff)
		binary.LittleEndian.PutUint64(rdata[intOff+uint32(index*8):], value)
		binary.LittleEndian.PutUint64(rdata[iatOff+uint32(index*8):], value)
	}
	copy(rdata[dllNameOff:], "KERNEL32.dll\x00")
	copy(rdata[exitNameOff+2:], "ExitProcess\x00")
	copy(rdata[stdNameOff+2:], "GetStdHandle\x00")
	copy(rdata[writeNameOff+2:], "WriteFile\x00")
}

func buildPEHeaders(header []byte, machine uint16, entryRVA uint32) {
	binary.LittleEndian.PutUint16(header[0:], 0x5a4d)
	binary.LittleEndian.PutUint32(header[0x3c:], 0x80)
	copy(header[0x80:], "PE\x00\x00")
	coff := header[0x84:]
	binary.LittleEndian.PutUint16(coff[0:], machine)
	binary.LittleEndian.PutUint16(coff[2:], 3)
	binary.LittleEndian.PutUint16(coff[16:], 0xf0)
	binary.LittleEndian.PutUint16(coff[18:], 0x22)

	optional := coff[20:]
	binary.LittleEndian.PutUint16(optional[0:], 0x20b)
	optional[2], optional[3] = 1, 0
	binary.LittleEndian.PutUint32(optional[4:], peSectionSize)
	binary.LittleEndian.PutUint32(optional[8:], 2*peSectionSize)
	binary.LittleEndian.PutUint32(optional[16:], entryRVA)
	binary.LittleEndian.PutUint32(optional[20:], peTextRVA)
	binary.LittleEndian.PutUint64(optional[24:], peImageBase)
	binary.LittleEndian.PutUint32(optional[32:], 0x1000)
	binary.LittleEndian.PutUint32(optional[36:], peSectionSize)
	binary.LittleEndian.PutUint16(optional[40:], 6)
	binary.LittleEndian.PutUint16(optional[48:], 6)
	binary.LittleEndian.PutUint32(optional[56:], 0x4000)
	binary.LittleEndian.PutUint32(optional[60:], peHeadersSize)
	binary.LittleEndian.PutUint16(optional[68:], 3)
	binary.LittleEndian.PutUint16(optional[70:], 0x100)
	binary.LittleEndian.PutUint64(optional[72:], 1<<20)
	binary.LittleEndian.PutUint64(optional[80:], 0x1000)
	binary.LittleEndian.PutUint64(optional[88:], 1<<20)
	binary.LittleEndian.PutUint64(optional[96:], 0x1000)
	binary.LittleEndian.PutUint32(optional[108:], 16)
	// Import, TLS, and IAT data directories.
	putDirectory(optional, 1, peRDataRVA, 40)
	putDirectory(optional, 9, peRDataRVA+peTLSDirectoryOff, 40)
	putDirectory(optional, 12, peRDataRVA+0x80, 32)

	sections := optional[0xf0:]
	putSection(sections[0:40], ".text", peSectionSize, peTextRVA, peSectionSize, peHeadersSize, 0x60000020)
	putSection(sections[40:80], ".rdata", peSectionSize, peRDataRVA, peSectionSize, peHeadersSize+peSectionSize, 0x40000040)
	putSection(sections[80:120], ".data", peSectionSize, peDataRVA, peSectionSize, peHeadersSize+2*peSectionSize, 0xc0000040)
}

func putDirectory(optional []byte, index int, rva, size uint32) {
	off := 112 + index*8
	binary.LittleEndian.PutUint32(optional[off:], rva)
	binary.LittleEndian.PutUint32(optional[off+4:], size)
}

func putSection(dst []byte, name string, virtualSize, rva, rawSize, rawOffset, characteristics uint32) {
	copy(dst[:8], name)
	binary.LittleEndian.PutUint32(dst[8:], virtualSize)
	binary.LittleEndian.PutUint32(dst[12:], rva)
	binary.LittleEndian.PutUint32(dst[16:], rawSize)
	binary.LittleEndian.PutUint32(dst[20:], rawOffset)
	binary.LittleEndian.PutUint32(dst[36:], characteristics)
}

func generateAMD64Text() ([]byte, uint32, error) {
	code := make([]byte, 0, peSectionSize)
	emit := func(values ...byte) { code = append(code, values...) }
	disp32Trailing := func(targetRVA uint32, trailingBytes uint32) {
		nextRVA := peTextRVA + uint32(len(code)) + 4 + trailingBytes
		value := int64(targetRVA) - int64(nextRVA)
		binaryValue := uint32(int32(value))
		emit(byte(binaryValue), byte(binaryValue>>8), byte(binaryValue>>16), byte(binaryValue>>24))
	}
	disp32 := func(targetRVA uint32) { disp32Trailing(targetRVA, 0) }
	callIAT := func(slot uint32) { emit(0xff, 0x15); disp32(peRDataRVA + 0x80 + slot*8) }
	lea := func(prefix []byte, target uint32) { emit(prefix...); disp32(target) }
	write := func(markerRVA uint32, length byte) {
		emit(0xb9, 0xf5, 0xff, 0xff, 0xff)
		callIAT(1)
		emit(0x48, 0x89, 0xc1)
		lea([]byte{0x48, 0x8d, 0x15}, markerRVA)
		emit(0x41, 0xb8, length, 0, 0, 0)
		lea([]byte{0x4c, 0x8d, 0x0d}, peDataRVA+peWrittenOff)
		emit(0x48, 0xc7, 0x44, 0x24, 0x20, 0, 0, 0, 0)
		callIAT(2)
	}

	// TLS callback: reason is EDX. Process attach is 1.
	emit(0x83, 0xfa, 0x01, 0x75, 0)
	callbackJNE := len(code) - 1
	emit(0x48, 0x83, 0xec, 0x38)
	write(peRDataRVA+peCallbackMsgOff, byte(len(callbackMarker)))
	emit(0xc6, 0x05)
	disp32Trailing(peDataRVA+peCallbackFlagOff, 1)
	emit(0x01, 0x48, 0x83, 0xc4, 0x38)
	callbackReturn := len(code)
	emit(0xc3)
	code[callbackJNE] = byte(callbackReturn - (callbackJNE + 1))

	for len(code) < 0x100 {
		emit(0x90)
	}
	entryOff := uint32(len(code))
	emit(0x48, 0x83, 0xec, 0x38, 0x80, 0x3d)
	disp32Trailing(peDataRVA+peCallbackFlagOff, 1)
	emit(0x01, 0x75, 0)
	entryJNE := len(code) - 1
	write(peRDataRVA+peMainMsgOff, byte(len(mainMarker)))
	emit(0x31, 0xc9)
	callIAT(0)
	fail := len(code)
	emit(0xb9, 0x01, 0, 0, 0)
	callIAT(0)
	emit(0xcc)
	code[entryJNE] = byte(fail - (entryJNE + 1))
	return code, entryOff, nil
}

type arm64Builder struct {
	words []uint32
}

func (b *arm64Builder) rva() uint32      { return peTextRVA + uint32(len(b.words)*4) }
func (b *arm64Builder) emit(word uint32) { b.words = append(b.words, word) }
func (b *arm64Builder) adrp(rd uint32, targetRVA uint32) {
	delta := int64(targetRVA&^0xfff) - int64(b.rva()&^0xfff)
	pages := delta >> 12
	imm := uint64(pages) & 0x1fffff
	b.emit(0x90000000 | uint32((imm&3)<<29) | uint32(((imm>>2)&0x7ffff)<<5) | rd)
}
func (b *arm64Builder) add(rd, rn, immediate uint32) {
	b.emit(0x91000000 | (immediate << 10) | (rn << 5) | rd)
}
func (b *arm64Builder) loadIAT(slot, targetRegister uint32) {
	target := peRDataRVA + 0x80 + slot*8
	b.adrp(targetRegister, target)
	b.emit(0xf9400000 | ((target&0xfff)/8)<<10 | targetRegister<<5 | targetRegister)
}
func (b *arm64Builder) branchCond(condition uint32) int {
	index := len(b.words)
	b.emit(0x54000000 | condition)
	return index
}
func (b *arm64Builder) patchBranch(index, target int) {
	offsetWords := int32(target - index)
	b.words[index] = (b.words[index] & 0xff00001f) | (uint32(offsetWords)&0x7ffff)<<5
}
func (b *arm64Builder) address(rd uint32, target uint32) {
	b.adrp(rd, target)
	b.add(rd, rd, target&0xfff)
}
func (b *arm64Builder) write(marker uint32, length uint32) {
	b.emit(0x12800000 | (10 << 5)) // movn w0, #10 => STD_OUTPUT_HANDLE (-11)
	b.loadIAT(1, 16)
	b.emit(0xd63f0200) // blr x16
	b.address(1, marker)
	b.emit(0x52800000 | (length << 5) | 2)
	b.address(3, peDataRVA+peWrittenOff)
	b.emit(0x52800004) // movz w4, #0
	b.loadIAT(2, 16)
	b.emit(0xd63f0200)
}

func generateARM64Text() ([]byte, uint32, error) {
	var b arm64Builder
	b.emit(0xa9bf7bfd) // stp x29, x30, [sp, #-16]!
	b.emit(0x910003fd) // mov x29, sp
	b.emit(0x7100043f) // cmp w1, #1
	callbackJNE := b.branchCond(1)
	b.write(peRDataRVA+peCallbackMsgOff, uint32(len(callbackMarker)))
	b.address(9, peDataRVA+peCallbackFlagOff)
	b.emit(0x5280002a) // movz w10, #1
	b.emit(0x3900012a) // strb w10, [x9]
	callbackReturn := len(b.words)
	b.emit(0xa8c17bfd) // ldp x29, x30, [sp], #16
	b.emit(0xd65f03c0) // ret
	b.patchBranch(callbackJNE, callbackReturn)
	for len(b.words) < 0x40 {
		b.emit(0xd503201f) // nop
	}
	entryOff := uint32(len(b.words) * 4)
	b.emit(0xa9bf7bfd)
	b.emit(0x910003fd)
	b.address(9, peDataRVA+peCallbackFlagOff)
	b.emit(0x3940012a) // ldrb w10, [x9]
	b.emit(0x7100055f) // cmp w10, #1
	entryJNE := b.branchCond(1)
	b.write(peRDataRVA+peMainMsgOff, uint32(len(mainMarker)))
	b.emit(0x52800000) // movz w0, #0
	b.loadIAT(0, 16)
	b.emit(0xd63f0200)
	fail := len(b.words)
	b.emit(0x52800020) // movz w0, #1
	b.loadIAT(0, 16)
	b.emit(0xd63f0200)
	b.emit(0xd4200000) // brk #0
	b.patchBranch(entryJNE, fail)
	code := make([]byte, len(b.words)*4)
	for index, word := range b.words {
		binary.LittleEndian.PutUint32(code[index*4:], word)
	}
	return code, entryOff, nil
}

func InspectTLSFixture(file *pe.File) (TLSFixtureInfo, error) {
	optional, ok := file.OptionalHeader.(*pe.OptionalHeader64)
	if !ok {
		return TLSFixtureInfo{}, fmt.Errorf("fixture is not PE32+")
	}
	tls := optional.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_TLS]
	if tls.VirtualAddress == 0 || tls.Size < 40 {
		return TLSFixtureInfo{}, fmt.Errorf("fixture has no PE TLS directory")
	}
	tlsData, err := readRVA(file, tls.VirtualAddress, 40)
	if err != nil {
		return TLSFixtureInfo{}, fmt.Errorf("read TLS directory: %w", err)
	}
	callbackArrayVA := binary.LittleEndian.Uint64(tlsData[24:])
	if callbackArrayVA < optional.ImageBase {
		return TLSFixtureInfo{}, fmt.Errorf("invalid TLS callback array VA %#x", callbackArrayVA)
	}
	callbackData, err := readRVA(file, uint32(callbackArrayVA-optional.ImageBase), 16)
	if err != nil {
		return TLSFixtureInfo{}, fmt.Errorf("read TLS callback array: %w", err)
	}
	callbackVA := binary.LittleEndian.Uint64(callbackData)
	if callbackVA == 0 {
		return TLSFixtureInfo{}, fmt.Errorf("TLS callback array is empty")
	}
	if binary.LittleEndian.Uint64(callbackData[8:]) != 0 {
		return TLSFixtureInfo{}, fmt.Errorf("TLS callback array is not null terminated")
	}
	if callbackVA < optional.ImageBase {
		return TLSFixtureInfo{}, fmt.Errorf("invalid TLS callback VA %#x", callbackVA)
	}
	if _, err := readRVA(file, uint32(callbackVA-optional.ImageBase), 1); err != nil {
		return TLSFixtureInfo{}, fmt.Errorf("TLS callback does not point into the image: %w", err)
	}
	all, err := io.ReadAll(io.NewSectionReader(file.Sections[1], 0, int64(file.Sections[1].Size)))
	if err != nil {
		return TLSFixtureInfo{}, err
	}
	info := TLSFixtureInfo{Machine: file.Machine, EntryPointRVA: optional.AddressOfEntryPoint, CallbackVA: callbackVA}
	if bytes.Contains(all, []byte(callbackMarker)) {
		info.CallbackMarker = callbackMarker
	}
	if bytes.Contains(all, []byte(mainMarker)) {
		info.MainMarker = mainMarker
	}
	return info, nil
}

func readRVA(file *pe.File, rva, size uint32) ([]byte, error) {
	for _, section := range file.Sections {
		if rva < section.VirtualAddress || rva+size > section.VirtualAddress+section.Size {
			continue
		}
		data, err := section.Data()
		if err != nil {
			return nil, err
		}
		off := rva - section.VirtualAddress
		return data[off : off+size], nil
	}
	return nil, fmt.Errorf("RVA %#x size %#x is outside sections", rva, size)
}
