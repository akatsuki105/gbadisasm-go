package gbadis

import "fmt"

func todo() {
	panic("todo")
}

func unused(v ...interface{}) {}

func byteAt(src []byte, addr uint32) byte {
	return src[addr-startAddr]
}

func hwordAt(src []byte, addr uint32) uint16 {
	lo := uint16(byteAt(src, addr))
	hi := uint16(byteAt(src, addr+1))
	return (hi << 8) | lo
}

func wordAt(src []byte, addr uint32) uint32 {
	b0 := uint32(byteAt(src, addr))
	b1 := uint32(byteAt(src, addr+1))
	b2 := uint32(byteAt(src, addr+2))
	b3 := uint32(byteAt(src, addr+3))
	return (b3 << 24) | (b2 << 16) | (b1 << 8) | b0
}

func assert(b bool, msg string) {
	if !b {
		if msg == "" {
			panic("assert failed")
		}
		panic(fmt.Sprintf("assert failed: %s", msg))
	}
}

func pcofs(mode LabelType) uint32 {
	if mode == ArmCode {
		return 8
	}
	return 4
}

func isSpace(c byte) bool {
	switch c {
	case ' ', '\t':
		return true
	}
	return false
}
