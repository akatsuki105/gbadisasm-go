package gbadis

import "math"

const (
	unknownSize   = math.MaxUint32
	startAddr     = 0x0800_0000
	dismAllocSize = 0x1000

	// .byte 0xNN * 16
	// .byte 0xNN * 16
	gOptionDataColumnWidth = 16

	gOptionShowAddrComments = false
	nop                     = 0x46c0 // mov r8, r8
)
