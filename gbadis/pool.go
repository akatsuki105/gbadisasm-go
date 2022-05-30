package gbadis

import g "github.com/pokemium/gapstone"

/*
	リテラルプール(Pool)

	LDR命令はLDR r0, =0xBEEFのように書くことで定数の代入にも使える。
	また、ラベルを用いてLDR r0, =labelのように書くことでラベルの位置のアドレスを代入することもできる。
	このとき、代入される値はアセンブル時にプログラム末尾にデータとして追記され、このデータを用いたLDR命令に書き換えられる。 このデータ部はリテラルプールと呼ばれる。

	引用元: https://inaz2.hatenablog.com/entry/2015/03/06/020239

	ldr r4, _080001FC @ =0x02000014

	...

@ _080001FC is pool
_080001FC: .4byte 0x02000014
*/

// is_pool_load
// "ldr rX, [pc, ?]" かどうかチェック
func isPoolLoad(insn *g.Instruction) bool {
	arminsn := insn.Arm

	if len(arminsn.Operands) < 2 {
		return false
	}
	ope0, ope1 := arminsn.Operands[0], arminsn.Operands[1]

	isLDR := insn.Id == g.ARM_INS_LDR
	isRxMem := ope0.Type == g.ARM_OP_REG && ope1.Type == g.ARM_OP_MEM

	return isLDR && isRxMem && !ope1.Subtracted && ope1.Mem.Base == g.ARM_REG_PC && ope1.Mem.Index == g.ARM_REG_INVALID
}

// get_pool_load
// "ldr rX, [pc, ?]"の`pc+?`を取得する
func getPoolLoad(insn *g.Instruction, currAddr uint32, mode LabelType) uint32 {
	assert(isPoolLoad(insn), "")

	currAddr = currAddr & 0xffff_fffc
	return uint32(int(currAddr) + insn.Arm.Operands[1].Mem.Disp + int(pcofs(mode)))
}
