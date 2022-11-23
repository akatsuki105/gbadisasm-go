package main

import (
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
	fmt.Println("ROM:    ", romPath)
	data, err := os.ReadFile(romPath)
	if err != nil {
		panic(err)
	}
	gbadis.SetROM(data)

	// gbadis(C)'s command arguments
	args := []string{romPath}

	cfgPath := fmt.Sprintf("./tests/%s/%s.cfg", name, name)
	if cfg, err := os.Open(cfgPath); err == nil {
		fmt.Println("Config: ", cfgPath)
		gbadis.ReadConfig(cfg)
		args = []string{"-c", cfgPath, romPath}
	}

	actual, expected := make(chan string), make(chan string)
	go func() {
		// gbadisgo
		actual <- strings.Join(gbadis.Disassemble(), "")
	}()
	go func() {
		// gbadis(C)
		fmt.Println("Command: ./tests/gbadisasm", strings.Join(args, " "))
		out, err := exec.Command("./tests/gbadisasm", args...).Output()
		if err != nil {
			panic(err)
		}
		expected <- string(out)
	}()

	if err := compare(<-actual, <-expected); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return ExitCodeError
	}

	fmt.Println("OK")
	return ExitCodeOK
}

func compare(a, b string) error {
	als, bls := strings.Split(a, "\n"), strings.Split(b, "\n")

	for l := 0; l < len(als); l++ {
		if als[l] != bls[l] {
			return fmt.Errorf(`line:%d don't match
	Actual: %s
	Expected: %s
`, l, als[l], bls[l])
		}
	}

	if len(als) != len(bls) {
		return fmt.Errorf("line counts don't match: (a, b) = (%d, %d)", len(als), len(bls))
	}

	return nil
}
