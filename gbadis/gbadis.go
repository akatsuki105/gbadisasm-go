package gbadis

import (
	"fmt"

	g "github.com/pokemium/gapstone"
)

var (
	sCapstone g.Engine
	gRom      = []byte{}
)

func SetROM(data []byte) {
	gRom = data
}

func Disassemble() string {
	cs, err := g.New(
		g.CS_ARCH_ARM,
		g.CS_MODE_ARM,
	)
	if err != nil {
		panic(fmt.Sprintf("cs_open failed %v\n", err))
	}
	sCapstone = cs

	cs.SetOption(g.CS_OPT_DETAIL, g.CS_OPT_ON)

	addLabel(startAddr, ArmCode, "") // entry point
	addLabel(startAddr+4, Data, "")  // rom header

	analyze()
	return printDisassembly()
}

func analyze() {
	for {
		li := getUnprocessedLabelIdx()
		if li < 0 {
			return
		}
		addr, t := gLabels[li].addr, gLabels[li].t

		if t.isCode() {
			sCapstone.SetOption(g.CS_OPT_MODE, t.csMode())
			sJt.phase = 0

			var running bool
			for {
				running, addr = analyzeCodeBlock(addr, t)
				if !running {
					break
				}
			}

			gLabels[li].processed = true
			gLabels[li].size = addr - gLabels[li].addr
		}
		gLabels[li].processed = true
	}
}

func analyzeCodeBlock(addr uint32, t LabelType) (bool, uint32) {
	ofs := addr - startAddr
	insns, err := sCapstone.Disasm(gRom[ofs:ofs+0x1000], uint64(addr), 0)
	if err != nil {
		panic(err)
	}

	for i := range insns {
	no_inc:

		insn := &insns[i]
		if !isValidInstruction(insn, t) {
			if t != ThumbCode {
				addr += 4
				continue
			}

			// 2bytes data
			addr += 2
			if insn.Size == 2 {
				continue
			}

			// Retry to analyze the two bytes after the incorrect data.
			ofs := addr - startAddr
			tmp, err := sCapstone.Disasm(gRom[ofs:ofs+2], uint64(addr), 0)
			if err != nil {
				panic(err)
			}
			assert(len(tmp) == 1, "")
			insns[i] = tmp[0]
			goto no_inc
		}

		sJt.check(insn)

		addr += uint32(insn.Size)

		// For BX{COND}, only BXAL can be considered as end of function
		if isFuncReturn(insn) {
			if l := lookupLabel(addr); l != nil {
				if l.t.isCode() && l.t != t && l.branchType == B {
					l.branchType = BL
					l.isFunc = true
				}
			}

			// If return, no further code will be executed
			break
		}

		if isBranch(insn) {
			// Already checked if bx is `BXAL` at isFuncReturn
			if insn.Id == g.ARM_INS_BX {
				continue // In the case of BX{COND}, further code may also be executed
			}

			// 分岐先アドレスにラベルを追加
			target := getBranchTarget(insn)
			assert(target != 0, "")

			// I don't remember why I needed this condition
			//if (!(target >= gLabels[li].addr && target <= currAddr))
			{
				lbl := addLabel(target, t, "")

				// do nothing if it's 100% a func (from func ptr, or instant mode exchange)
				if !lbl.isFunc {
					if insn.Id == g.ARM_INS_BL {
						if lbl.branchType != B {
							lbl.branchType = BL
						}

						// 直後のアドレスがpoolであれば、これは関数呼び出しではなく、 far jump であることがわかります。
						// if the address right after is a pool, then we know for sure that this is a far jump and not a function call
						next := lookupLabel(addr)
						if (next != nil && next.t == Pool) || hwordAt(gRom, addr) == 0 {
							lbl.branchType = B
							break
						}
					} else {
						// ラベルは.cfgファイルで名前が与えられているかもしれないが、実際には関数ではない
						lbl.name = ""
						lbl.branchType = B
					}
				}
			}

			// When `BAL`, `BXAL`, no further code will be executed, so go to next block
			if insn.Arm.CC == g.ARM_CC_AL && insn.Id != g.ARM_INS_BL {
				break
			}
		} else {
			assert(insn.Arm != nil, "")

			// `add rX, [pc, offset]`かどうか(Thumbモード用)
			if insn.Id == g.ARM_INS_ADR {
				opes := insn.Arm.Operands
				currAddr := addr - uint32(insn.Size)
				word := uint32(opes[1].Imm) + currAddr + pcofs(t)
				if t == ThumbCode {
					word &= 0xffff_fffc
				}
				checkHandwrittenIndirectJump(insns, i, t, word)
				continue
			}

			// `add rX, [pc, offset]`かどうか(Armモード用)
			if t == ArmCode {
				opes := insn.Arm.Operands
				currAddr := addr - uint32(insn.Size)
				isADD := insn.Id == g.ARM_INS_ADD
				if len(opes) >= 3 {
					isRR := opes[0].Type == g.ARM_OP_REG && opes[1].Type == g.ARM_OP_REG
					isPcImm := opes[1].Reg == g.ARM_REG_PC && opes[2].Type == g.ARM_OP_IMM
					if isADD && isRR && isPcImm {
						word := uint32(opes[2].Imm) + currAddr + 8
						checkHandwrittenIndirectJump(insns, i, t, word)
						continue
					}
				}
			}

			// `ldr rX, [pc, ?]` かどうか
			if isPoolLoad(insn) {
				currAddr := addr - uint32(insn.Size)
				poolAddr := getPoolLoad(insn, currAddr, t)
				assert(poolAddr != 0, "")
				assert(poolAddr&3 == 0, "")
				addLabel(poolAddr, Pool, "")
				word := wordAt(gRom, poolAddr)

				// 結局ここにくるのは、何らかのジャンプのとき(word にはジャンプで飛んでくるアドレスが書いてある)
				// 具体的には、insn[i]が、
				//   case 1: add rX, [pc, offset]
				//   case 2: ldr rX, [pc, offset]
				checkHandwrittenIndirectJump(insns, i, t, word)
			}
		}
	}

	return len(insns) == dismAllocSize, addr
}

func isValidInstruction(insn *g.Instruction, t LabelType) bool {
	included := func(insn *g.Instruction, group uint) bool {
		groups := insn.Groups
		for _, g := range groups {
			if g == group {
				return true
			}
		}
		return false
	}

	if included(insn, g.ARM_GRP_V4T) {
		return true
	}

	if t == ArmCode {
		return included(insn, g.ARM_GRP_ARM)
	}

	return included(insn, g.ARM_GRP_THUMB)
}

// b, bl, bx
func isBranch(insn *g.Instruction) bool {
	switch insn.Id {
	case g.ARM_INS_B, g.ARM_INS_BL, g.ARM_INS_BX:
		return true
	}
	return false
}

// bx rX
//
// mov pc, ?
//
// pop { .., pc }
func isFuncReturn(insn *g.Instruction) bool {
	arminsn := insn.Arm

	// 'bx'命令のとき 無条件ジャンプならtrue
	if insn.Id == g.ARM_INS_BX {
		return arminsn.CC == g.ARM_CC_AL
	}

	// pcをdstとする'mov'命令のとき
	if insn.Id == g.ARM_INS_MOV {
		ope := &arminsn.Operands[0]
		if ope.Type == g.ARM_OP_REG && ope.Reg == g.ARM_REG_PC {
			return true
		}
	}

	// 'pop'命令のとき pcにもpopするかどうか
	if insn.Id == g.ARM_INS_POP {
		for _, ope := range arminsn.Operands {
			if ope.Type == g.ARM_OP_REG && ope.Reg == g.ARM_REG_PC {
				return true
			}
		}
	}

	return false
}

// get_branch_target
func getBranchTarget(insn *g.Instruction) uint32 {
	target := uint32(insn.Arm.Operands[0].Imm)
	return target
}

// check_handwritten_indirect_jump
func checkHandwrittenIndirectJump(insns []g.Instruction, i int, t LabelType, word uint32) {
	if i < len(insns)-1 {
		insn := &insns[i]
		opes := insns[i+1].Arm.Operands

		isBX := insns[i+1].Id == g.ARM_INS_BX
		if isBX {
			isReg := opes[0].Type == g.ARM_OP_REG
			isJumpTargetPreviousReg := insn.Arm.Operands[0].Reg == opes[0].Reg
			if isReg && isJumpTargetPreviousReg {
				mode := ArmCode
				if word&1 > 0 {
					mode = ThumbCode
				}
				renewOrAddNewFuncLabel(mode, word)
			}
			return
		}

		isMOV := insns[i+1].Id == g.ARM_INS_MOV
		isPcRx := opes[0].Type == g.ARM_OP_REG && opes[0].Reg == g.ARM_REG_PC && opes[1].Type == g.ARM_OP_REG
		if isMOV && isPcRx {
			isJumpTargetPreviousReg := insn.Arm.Operands[0].Reg == opes[1].Reg
			if isJumpTargetPreviousReg {
				renewOrAddNewFuncLabel(t, word)
			}
		}
	}
}
