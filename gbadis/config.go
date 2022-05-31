package gbadis

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

type Token string

const (
	armFunc   Token = "arm_func"
	thumbFunc Token = "thumb_func"
	fileBegin Token = "file_begin"
)

var labelTypes = map[Token]LabelType{
	"arm_func":   ArmCode,
	"thumb_func": ThumbCode,
}

type asmFile struct {
	addr uint32
	name string
}

var gFileBegins = []asmFile{
	{
		addr: 0x08000000,
		name: "main",
	},
}

func Files() []string {
	names := make([]string, len(gFileBegins))
	for i, asm := range gFileBegins {
		names[i] = asm.name
	}
	return names
}

func ReadConfig(r io.Reader) {
	data, err := io.ReadAll(r)
	if err != nil {
		panic(err)
	}

	lines := strings.Split(string(data), "\n")
	for l, line := range lines {
		for i := range line {
			if !isSpace(line[i]) {
				line = line[i:]
				break
			}
		}

		// 空行 or コメント行
		if len(line) == 0 || line[0] == '#' {
			continue
		}

		tokens := strings.Split(line, " ")
		switch d := Token(tokens[0]); d {
		// e.g. thumb_func 0x080196b8 CopyStageState
		case armFunc, thumbFunc:
			addr, err := strconv.ParseUint(tokens[1][2:], 16, 32)
			if err != nil {
				fmt.Fprintf(os.Stderr, "syntax error on line %d\n", l)
				continue
			}
			if len(tokens) >= 3 && tokens[2] != "" {
				addLabel(uint32(addr), labelTypes[d], tokens[2])
			}

		// e.g. file_begin 0x080196b8
		case fileBegin:
			addr, err := strconv.ParseUint(tokens[1][2:], 16, 32)
			if err != nil {
				fmt.Fprintf(os.Stderr, "syntax error on line %d\n", l)
				continue
			}
			gFileBegins = append(gFileBegins, asmFile{
				addr: uint32(addr),
				name: tokens[2],
			})

		default:
			fmt.Fprintf(os.Stderr, "warning: unrecognized command '%s' on line %d\n", d, l)
		}
	}
}
