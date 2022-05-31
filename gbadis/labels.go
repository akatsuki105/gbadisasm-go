package gbadis

import (
	"fmt"

	g "github.com/pokemium/gapstone"
)

type LabelType byte

const (
	ArmCode LabelType = iota
	ThumbCode
	Data
	Pool
	JumpTable
)

func (l LabelType) isCode() bool {
	return l == ArmCode || l == ThumbCode
}

func (l LabelType) csMode() uint {
	if l == ArmCode {
		return g.CS_MODE_ARM
	}
	return g.CS_MODE_THUMB
}

func (l LabelType) String() string {
	switch l {
	case ArmCode:
		return "arm"
	case ThumbCode:
		return "thumb"
	case Data:
		return "data"
	case Pool:
		return "pool"
	case JumpTable:
		return "jump_table"
	default:
		return "unknown"
	}
}

type BranchType byte

const (
	Unknown BranchType = iota
	B
	BL
)

type Label struct {
	name       string
	addr       uint32
	t          LabelType
	branchType BranchType
	size       uint32
	processed  bool
	isFunc     bool
}

var gLabels = []*Label{}

func getUnprocessedLabelIdx() int {
	for i := range gLabels {
		if !gLabels[i].processed {
			return i
		}
	}

	return -1
}

func lookupLabel(addr uint32) *Label {
	for _, l := range gLabels {
		if l.addr == addr {
			return l
		}
	}
	return nil
}

func (l *Label) String() string {
	name := l.name
	if name == "" {
		name = fmt.Sprintf("L_%08x", l.addr)
	}
	return fmt.Sprintf(`label:
  name: %s
  type: %s
  addr: %08x
  size: %dBytes
`, name, l.t, l.addr, l.size)
}

// This func is a clone of disasm_add_label
func addLabel(addr uint32, t LabelType, name string) *Label {
	for _, l := range gLabels {
		if l.addr == addr {
			l.t = t
			return l
		}
	}

	l := &Label{
		addr:       addr,
		t:          t,
		branchType: Unknown,
		size:       unknownSize,
		name:       name,
	}
	if t.isCode() {
		l.branchType = BL
	}

	gLabels = append(gLabels, l)
	return l
}

// renew_or_add_new_func_label
func renewOrAddNewFuncLabel(t LabelType, word uint32) {
	if word&startAddr != 0 {
		l := lookupLabel(word & 0xffff_fffe)
		if l == nil {
			// 暗黙的に BRANCH_TYPE_BL に設定される
			l := addLabel(word&0xffff_fffe, t, "")
			l.isFunc = true
			return
		}

		// 非関数ラベルとして処理されている可能性がある
		l.processed = false
		l.branchType = BL
		l.isFunc = true
	}
}
