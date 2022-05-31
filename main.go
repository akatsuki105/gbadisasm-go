package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/pokemium/gbadisasm-go/gbadis"
)

var version string

const (
	title = "gbadisgo"
)

// ExitCode represents program's status code
type ExitCode int

// exit code
const (
	ExitCodeOK ExitCode = iota
	ExitCodeError
)

func init() {
	if version == "" {
		version = "develop"
	}

	flag.Usage = func() {
		usage := fmt.Sprintf(`Usage:
    %s [arg] [input]
input: a filepath
Arguments: 
`, title)

		fmt.Fprint(os.Stderr, usage)
		flag.PrintDefaults()
	}
}

func main() {
	os.Exit(int(Run()))
}

// Run program
func Run() ExitCode {
	var (
		showVersion = flag.Bool("v", false, "show version")
		configPath  = flag.String("c", "", "cfg file path")
		// allFlag     = flag.Bool("a", false, "generate directories including macros")
	)

	flag.Parse()
	if *showVersion {
		printVersion()
		return ExitCodeOK
	}

	if flag.NArg() == 0 {
		fmt.Fprint(os.Stderr, "usage: gbadis ROM_PATH")
	}

	data, err := os.ReadFile(flag.Arg(0))
	if err != nil {
		panic(err)
	}
	gbadis.SetROM(data)

	if *configPath != "" {
		f, err := os.Open(*configPath)
		if err != nil {
			panic(err)
		}
		gbadis.ReadConfig(f)
	}

	fmt.Print(gbadis.Disassemble())
	return ExitCodeOK
}

func printVersion() {
	fmt.Println(title+":", version)
}
