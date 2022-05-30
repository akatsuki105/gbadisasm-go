package gbadis

import (
	"math"

	g "github.com/pokemium/gapstone"
)

/*
	Jump table is a following code block.

	lsl rX, rX, 2
	ldr rX, [pc, ?] @ pc+? refers to Pool
	add rX, rX, rY
	mov pc, rX

Pool: .4byte Jt

Jt:
	func_0
	func_1
	func_2
	func_3
*/

type JumpTableAnalyzer struct {
	phase         uint
	begin         uint32
	inGracePeriod bool
	poolAddr      uint32
}

var sJt = &JumpTableAnalyzer{}

// jump_table_state_machine
func (j *JumpTableAnalyzer) check(insn *g.Instruction) {
	addr := uint32(insn.Address)
	match := false

	switch j.phase {
	// "lsl rX, rX, 2"
	case 0:
		j.inGracePeriod = false
		match = insn.Id == g.ARM_INS_LSL

	// "ldr rX, [pc, ?]"
	case 1:
		if isPoolLoad(insn) {
			j.poolAddr = getPoolLoad(insn, addr, ThumbCode)
			j.begin = wordAt(gRom, j.poolAddr)
			match = true
		}

	// "add rX, rX, rX"
	case 2:
		match = insn.Id == g.ARM_INS_ADD

	// "ldr rX, [rX]"
	case 3:
		match = insn.Id == g.ARM_INS_LDR

	// "mov pc, rX"
	case 4:
		if insn.Id == g.ARM_INS_MOV {
			ope := insn.Arm.Operands[0]
			match = ope.Type == g.ARM_OP_REG && ope.Reg == g.ARM_REG_PC
		}
	}

	// is not jump table
	if !match {
		if j.inGracePeriod {
			j.phase = 0
		} else {
			// other order may be in between.
			j.inGracePeriod = true
		}
		return
	}

	// all checks passed
	if j.phase == 4 {
		target := uint32(0)
		firstTarget := uint32(math.MaxUint32)

		// jump table is not in ROM, indicating it's from a library loaded into RAM
		if j.begin&startAddr == 0 {
			ofs := j.poolAddr + 4 - j.begin

			addLabel(j.poolAddr+4, JumpTable, "")
			addr = j.poolAddr + 4
			for addr < wordAt(gRom, j.poolAddr+4)+ofs {
				lbl := addLabel(wordAt(gRom, addr)+ofs, ThumbCode, "")
				lbl.branchType = B
				addr += 4
			}
			return
		}

		addLabel(j.begin, JumpTable, "")
		j.phase = 0

		// add code labels from jump table
		addr = j.begin
		for addr < firstTarget {
			target = wordAt(gRom, addr)
			if target-startAddr >= 0x02000000 {
				break
			}
			if target < firstTarget && target > j.begin {
				firstTarget = target
			}
			lbl := addLabel(target, ThumbCode, "")
			lbl.branchType = B
			addr += 4
		}

		return
	}
	j.phase++
}
