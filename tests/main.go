package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/pokemium/gbadisasm-go/gbadis"
)

// ExitCode represents program's status code
type ExitCode int

// exit code
const (
	ExitCodeOK ExitCode = iota
	ExitCodeError
)

func main() {
	os.Exit(int(Run()))
}

// Run program
func Run() ExitCode {
	flag.Parse()
	name := flag.Arg(0)
	if name == "" {
		fmt.Fprintf(os.Stderr, "Please input a target rom")
		return ExitCodeError
	}

	romPath := fmt.Sprintf("./tests/%s/%s.gba", name, name)
	data, err := os.ReadFile(romPath)
	if err != nil {
		panic(err)
	}
	gbadis.SetROM(data)

	args := []string{romPath}

	cfgPath := fmt.Sprintf("./tests/%s/%s.cfg", name, name)
	if cfg, err := os.Open(cfgPath); err == nil {
		gbadis.ReadConfig(cfg)
		args = append(args, "-c", cfgPath)
	}

	acutal := gbadis.Disassemble()
	out, err := exec.Command("./tests/gbadisasm", args...).Output()
	if err != nil {
		panic(err)
	}
	expected := string(out)

	if err := compare(acutal, expected); err != nil {
		fmt.Fprint(os.Stderr, err)
		return ExitCodeError
	}

	fmt.Println("OK")
	return ExitCodeOK
}

func compare(a, b string) error {
	als, bls := strings.Split(a, "\n"), strings.Split(b, "\n")
	if len(als) != len(bls) {
		return errors.New("line counts don't match")
	}

	for l := 0; l < len(als); l++ {
		if als[l] != bls[l] {
			return fmt.Errorf(`line:%d don't match
	Actual: %s
	Expected: %s
`, l, als[l], bls[l])
		}
	}

	return nil
}
