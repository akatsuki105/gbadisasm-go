package gbadis

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	g "github.com/pokemium/gapstone"
)

// print_disassembly
func printDisassembly() string {
	var b strings.Builder

	sort.Slice(gLabels, func(i, j int) bool {
		return gLabels[i].addr < gLabels[j].addr
	})

	for i := 0; i < len(gLabels)-1; i++ {
		// fmt.Printf("[%d]: %v\n", i, gLabels[i])
		assert(gLabels[i].addr < gLabels[i+1].addr, "")
	}

	for _, l := range gLabels {
		if l.t.isCode() {
			assert(l.processed, "")
		}
	}

	// check mode exchange right after func return
	for i := 1; i < len(gLabels); i++ {
		prev, curr := gLabels[i-1].t, gLabels[i].t
		if (prev == ArmCode && curr == ThumbCode) || (prev == ThumbCode && curr == ArmCode) {
			gLabels[i].branchType = BL
		}
	}

	i := 0
	addr := uint32(startAddr)
	for addr < uint32(startAddr+len(gRom)) {
		block := printBlock(i, addr)
		b.WriteString(block.result)
		addr = block.addr
		i++
		if block.isBreak {
			break
		}
	}

	return b.String()
}

type block struct {
	result  string
	addr    uint32
	isBreak bool
}

func printBlock(i int, addr uint32) block {
	var b strings.Builder

	l := gLabels[i]

	// TODO: compute actual size during analysis phase
	if i+1 < len(gLabels) {
		if l.size == unknownSize || l.addr+l.size > gLabels[i+1].addr {
			l.size = gLabels[i+1].addr - l.addr
		}
	}

	switch l.t {
	case ArmCode, ThumbCode:
		mode := l.t.csMode()

		if l.branchType == BL {
			// This is a function. Use the 'sub_XXXXXXXX' label
			unalignedMask := uint32(1)
			if mode == g.CS_MODE_ARM {
				unalignedMask = 3
			}

			if addr&unalignedMask > 0 {
				fmt.Fprintf(os.Stderr, "error: function at 0x%08X is not aligned\n", addr)
				return block{
					result:  b.String(),
					addr:    addr,
					isBreak: false,
				}
			}
			if l.name != "" {
				fmt.Fprintf(&b, "\n\t%s %s\n", funcMacro(l.t, addr), l.name)
				fmt.Fprintf(&b, "%s: @ 0x%08X\n", l.name, addr)
			} else {
				fmt.Fprintf(&b, "\n\t%s sub_%08X\n", funcMacro(l.t, addr), addr)
				fmt.Fprintf(&b, "sub_%08X: @ 0x%08X\n", addr, addr)
			}
		} else {
			// Just a normal code label. Use the '_XXXXXXXX' label
			if l.name != "" {
				fmt.Fprintf(&b, "%s:\n", l.name)
			} else {
				fmt.Fprintf(&b, "_%08X:\n", addr)
			}
		}

		assert(l.size != unknownSize, "")
		sCapstone.SetOption(g.CS_OPT_MODE, mode)
		insns, err := sCapstone.Disasm(gRom[addr-startAddr:addr-startAddr+l.size], uint64(addr), 0)
		if err != nil {
			panic(err)
		}
		for j := range insns {
		no_inc:
			insn := &insns[j]
			if !isValidInstruction(insn, l.t) {
				if l.t == ThumbCode {
					fmt.Fprintf(&b, "\t.hword 0x%04X\n", hwordAt(gRom, addr))
					addr += 2
					if insn.Size == 2 {
						continue
					}
					tmp, _ := sCapstone.Disasm(gRom[addr-startAddr:addr-startAddr+2], uint64(addr), 0)
					assert(len(tmp) == 1, "")
					insns[j] = tmp[0]
					goto no_inc
				} else {
					fmt.Fprintf(&b, "\t.word 0x%08X\n", wordAt(gRom, addr))
					addr += 4
					continue
				}
			}
			printInsn(&b, insn, l.t)
			addr += uint32(insn.Size)
		}

		// align pool if it comes next
		if i+1 < len(gLabels) && gLabels[i+1].t == Pool {
			diff := gLabels[i+1].addr - addr
			checkZero := func(addr, diff uint32) bool {
				for i := uint32(0); i < diff; i++ {
					if gRom[addr-startAddr+i] != 0 {
						return false
					}
				}
				return true
			}
			if diff == 0 || (int(diff) > 0 && diff < 4 && checkZero(addr, diff)) {
				fmt.Fprintln(&b, "\t.align 2, 0")
				addr += diff
			}
		}

	case Pool:
		val := wordAt(gRom, addr)

		// e.g. AgbMain+1
		if val&3 != 0 && val&startAddr != 0 {
			if l := lookupLabel(val & 0xffff_fffe); l != nil {
				if l.branchType == BL && l.t == ThumbCode {
					switch {
					case l.name != "":
						// _080FE5A8: .4byte AgbMain
						fmt.Fprintf(&b, "_%08X: .4byte %s\n", addr, l.name)

					default:
						fmt.Fprintf(&b, "_%08X: .4byte sub_%08X\n", addr, val&0xffff_fffe)
					}
					addr += 4
					return block{
						result:  b.String(),
						addr:    addr,
						isBreak: false,
					}
				}
			}
		}

		if l := lookupLabel(val); l != nil {
			if l.t != ThumbCode {
				switch {
				case l.name != "":
					// _080FE5A8: .4byte ReadSram_Core
					fmt.Fprintf(&b, "_%08X: .4byte %s\n", addr, l.name)

				case l.branchType == BL:
					fmt.Fprintf(&b, "_%08X: .4byte sub_%08X\n", addr, val)

				default:
					// _080FE2E8: .4byte _080FE2EC
					fmt.Fprintf(&b, "_%08X: .4byte _%08X\n", addr, val)
				}
				addr += 4
				return block{
					result:  b.String(),
					addr:    addr,
					isBreak: false,
				}
			}
		}

		// _080FE2B4: .4byte 0x68736D53
		fmt.Fprintf(&b, "_%08X: .4byte 0x%08X\n", addr, val)
		addr += 4

	/*
		_080025E8: @ jump table
			.4byte _080025FC @ case 0
			.4byte _0800260C @ case 1
			.4byte _08002624 @ case 2
			.4byte _08002660 @ case 3
			.4byte _0800266A @ case 4
	*/
	case JumpTable:
		end := addr + l.size

		// _080025E8: @ jump table
		fmt.Fprintf(&b, "_%08X: @ jump table\n", addr)

		caseNum := 0
		for addr < end {
			word := wordAt(gRom, addr)
			prefix := "_"
			if word&startAddr == 0 {
				prefix = "0x"
			}

			// .4byte _080025FC @ case N
			fmt.Fprintf(&b, "\t.4byte %s%08X @ case %d\n", prefix, word, caseNum)
			caseNum++
			addr += 4
		}
	}

	i++
	if i >= len(gLabels) {
		return block{
			result:  b.String(),
			addr:    addr,
			isBreak: true,
		}
	}
	nextAddr := gLabels[i].addr
	assert(addr <= nextAddr, fmt.Sprintf("[%d]: 0x%08x, [%d]: 0x%08x", i, addr, i+1, nextAddr))
	if nextAddr <= uint32(startAddr+len(gRom)) {
		printGap(&b, addr, nextAddr)
	}
	addr = nextAddr

	return block{
		result:  b.String(),
		addr:    addr,
		isBreak: false,
	}
}

// _08000164:
//         .byte 0xNN, 0xNN, ...
//         .byte 0xNN, 0xNN, ...
func printGap(w io.Writer, addr, nextAddr uint32) {
	if addr == nextAddr {
		return
	}

	assert(addr < nextAddr, "")

	// alignment
	if addr&3 == 2 {
		nextShort := hwordAt(gRom, addr)
		switch nextShort {
		case 0:
			fmt.Fprintln(w, "\t.align 2, 0")
			addr += 2
		case nop:
			fmt.Fprintln(w, "\tnop")
			addr += 2
		}
		if addr == nextAddr {
			return
		}
	}

	fmt.Fprintf(w, "_%08X:\n", addr)
	if addr%gOptionDataColumnWidth != 0 {
		fmt.Fprint(w, "\t.byte")
	}

	// .byte 0xNN, 0xNN, ...
	// .byte 0xNN, 0xNN, ...
	for addr < nextAddr {
		if addr%gOptionDataColumnWidth == 0 {
			fmt.Fprint(w, "\t.byte")
		}

		fmt.Fprintf(w, " 0x%02X", byteAt(gRom, addr))
		if addr%gOptionDataColumnWidth == (gOptionDataColumnWidth-1) || addr == nextAddr-1 {
			fmt.Fprint(w, "\n") // next line
		} else {
			fmt.Fprint(w, ",")
		}
		addr++
	}
}

func printInsn(w io.Writer, insn *g.Instruction, mode LabelType) {
	addr := uint32(insn.Address)
	if gOptionShowAddrComments {
		fmt.Fprintf(w, "\t/*0x%08X*/ %s %s\n", addr, insn.Mnemonic, insn.OpStr)
		return
	}

	switch {
	case isBranch(insn) && insn.Id != g.ARM_INS_BX:
		target := getBranchTarget(insn)
		lbl := lookupLabel(target)
		assert(lbl != nil, "")

		if lbl.name != "" {
			fmt.Fprintf(w, "\t%s %s\n", insn.Mnemonic, lbl.name)
		} else {
			prefix := ""
			if lbl.branchType == BL {
				prefix = "sub"
			}
			fmt.Fprintf(w, "\t%s %s_%08X\n", insn.Mnemonic, prefix, target)
		}

	case isPoolLoad(insn):
		word := getPoolLoad(insn, addr, mode)
		val := wordAt(gRom, word)

		// possibly thumb function
		if val&3 != 0 && val&startAddr != 0 {
			if lbl := lookupLabel(val & 0xffff_fffe); lbl != nil {
				if lbl.branchType == BL && lbl.t == ThumbCode {
					reg := sCapstone.RegName(insn.Arm.Operands[0].Reg)
					if lbl.name != "" {
						fmt.Fprintf(w, "\t%s %s, _%08X @ =%s\n", insn.Mnemonic, reg, word, lbl.name)
					} else {
						fmt.Fprintf(w, "\t%s %s, _%08X @ =sub_%08X\n", insn.Mnemonic, reg, word, val)
					}
					return
				}
			}
		}

		reg := sCapstone.RegName(insn.Arm.Operands[0].Reg)
		if lbl := lookupLabel(val); lbl != nil {
			if lbl.t != ThumbCode {
				switch {
				case lbl.name != "":
					fmt.Fprintf(w, "\t%s %s, _%08X @ =%s\n", insn.Mnemonic, reg, word, lbl.name)

				case lbl.branchType == BL:
					fmt.Fprintf(w, "\t%s %s, _%08X @ =sub_%08X\n", insn.Mnemonic, reg, word, val)

				default:
					// normal label
					fmt.Fprintf(w, "\t%s %s, _%08X @ =_%08X\n", insn.Mnemonic, reg, word, val)
				}
				return
			}
		}
		fmt.Fprintf(w, "\t%s %s, _%08X @ =0x%08X\n", insn.Mnemonic, reg, word, val)

	default:
		opes := insn.Arm.Operands
		switch {
		// fix "add rX, sp, rX"
		case insn.Id == g.ARM_INS_ADD && opes[0].Type == g.ARM_OP_REG && opes[1].Type == g.ARM_OP_REG && opes[1].Reg == g.ARM_REG_SP && opes[2].Type == g.ARM_OP_REG:
			reg0 := sCapstone.RegName(opes[0].Reg)
			reg1 := sCapstone.RegName(opes[1].Reg)
			fmt.Fprintf(w, "\t%s %s, %s\n", insn.Mnemonic, reg0, reg1)

		// fix thumb adr
		case insn.Id == g.ARM_INS_ADR && mode == ThumbCode:
			word := (uint32(opes[1].Imm) + addr + 4) & 0xffff_fffc
			if lbl := lookupLabel(word); lbl != nil {
				if lbl.t != ThumbCode {
					reg := sCapstone.RegName(opes[0].Reg)
					switch {
					case lbl.name != "":
						fmt.Fprintf(w, "\tadd %s, pc, #0x%X @ =%s\n", reg, opes[1].Imm, lbl.name)
					case lbl.branchType == BL:
						fmt.Fprintf(w, "\tadd %s, pc, #0x%X @ =sub_%08X\n", reg, opes[1].Imm, word)
					default:
						fmt.Fprintf(w, "\tadd %s, pc, #0x%X @ =_%08X\n", reg, opes[1].Imm, word)
					}
					return
				}
			}
			fmt.Fprintf(w, "\tadd %s, pc, #0x%X\n", sCapstone.RegName(opes[0].Reg), opes[1].Imm)

		// arm adr
		case mode == ArmCode && insn.Id == g.ARM_INS_ADD && opes[0].Type == g.ARM_OP_REG && opes[1].Type == g.ARM_OP_REG && opes[1].Reg == g.ARM_REG_PC && opes[2].Type == g.ARM_OP_IMM:
			imm := opes[2].Imm
			word := uint32(imm) + addr + 8

			if word&3 > 0 && word&startAddr > 0 {
				if lbl := lookupLabel(word & 0xffff_fffe); lbl != nil {
					if lbl.branchType == BL && lbl.t == ThumbCode {
						reg := sCapstone.RegName(opes[0].Reg)
						if lbl.name != "" {
							fmt.Fprintf(w, "\tadd %s, pc, #0x%X @ =%s\n", reg, imm, lbl.name)
						} else {
							fmt.Fprintf(w, "\tadd %s, pc, #0x%X @ =sub_%08X\n", reg, imm, word&0xffff_fffe)
						}
						return
					}
				}
			}

			lbl := lookupLabel(word)
			reg := sCapstone.RegName(opes[0].Reg)
			if lbl != nil {
				if lbl.t != ThumbCode {
					switch {
					case lbl.name != "":
						fmt.Fprintf(w, "\tadd %s, pc, #0x%X @ =%s\n", reg, imm, lbl.name)
					case lbl.branchType == BL:
						fmt.Fprintf(w, "\tadd %s, pc, #0x%X @ =sub_%08X\n", reg, imm, word)
					default:
						fmt.Fprintf(w, "\tadd %s, pc, #0x%X @ =_%08X\n", reg, imm, word)
					}
					return
				}
			}
			fmt.Fprintf(w, "\tadd %s, pc, #0x%X @ =0x%08X\n", reg, imm, word)

		default:
			fmt.Fprintf(w, "\t%s %s\n", insn.Mnemonic, insn.OpStr)
		}

	}
}

func funcMacro(mode LabelType, addr uint32) string {
	macro := ""
	switch mode {
	case ArmCode:
		macro = "arm_func_start"
	default:
		if addr&2 > 0 {
			macro = "non_word_aligned_thumb_func_start"
		} else {
			macro = "thumb_func_start"
		}
	}
	return macro
}
