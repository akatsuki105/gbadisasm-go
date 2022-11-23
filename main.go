package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/pokemium/gbadisasm-go/gbadis"
)

var prefix = `	.include "asm/macros.inc"

	.syntax unified
	
	.text
	`

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
    %s [OPTIONS] <ROM.gba>

OPTIONS: 
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
		configPath  = flag.String("c", "", "cfg file path (Default ROM.cfg)")
		outputDir   = flag.String("d", "", "output directory (e.g. asm)")
		alwayYes    = flag.Bool("y", false, "treat all confirmation as YES")
	)

	flag.Parse()
	if *showVersion {
		printVersion()
		return ExitCodeOK
	}

	if flag.NArg() == 0 {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] <ROM.gba>\n", title)
	}

	romPath := flag.Arg(0)
	data, err := os.ReadFile(romPath)
	if err != nil {
		panic(err)
	}
	gbadis.SetROM(data)

	// Read config file
	config := *configPath
	if config == "" {
		// Check default config path, ROM.cfg
		defaultConfigPath := strings.ReplaceAll(romPath, ".gba", ".cfg")
		if fileExist(defaultConfigPath) {
			config = defaultConfigPath
		}
	}
	if config != "" {
		fmt.Fprintln(os.Stderr, "Config file is found: "+config)
		f, err := os.Open(config)
		if err != nil {
			panic(err)
		}
		gbadis.ReadConfig(f)
	}

	asms := gbadis.Disassemble()

	if *outputDir == "" {
		// output stdout
		fmt.Print(strings.Join(asms, ""))
		return ExitCodeOK
	}

	// output into directory
	{
		filenames := gbadis.Files()

		// create or cleanup output dir
		dir := strings.TrimSuffix(*outputDir, "/")
		fmt.Println("Output directory: ", dir)
		if dirExist(dir) {
			// confirmation
			if !(*alwayYes) && !askYesNo("Directory already exists, delete all files?") {
				return ExitCodeError
			}
			os.RemoveAll(dir)
		}
		os.MkdirAll(dir, 0755)

		for i, asm := range asms {
			filepath := fmt.Sprintf("%s/%s.s", dir, filenames[i])

			f, err := os.OpenFile(filepath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
			if err != nil {
				panic(err)
			}
			defer f.Close()

			f.Write([]byte(prefix + asm))
		}
	}

	return ExitCodeOK
}

func printVersion() {
	fmt.Println(title+":", version)
}

// Check whether file exists
func fileExist(fp string) bool {
	if f, err := os.Stat(fp); os.IsNotExist(err) || f.IsDir() {
		return false
	}
	return true
}

// Check whether dir exists
func dirExist(dp string) bool {
	if f, err := os.Stat(dp); os.IsNotExist(err) || !f.IsDir() {
		return false
	}
	return true
}

func askYesNo(s string) bool {
	reader := bufio.NewReader(os.Stdin)

	fmt.Printf("%s [y/n]: ", s)

	response, err := reader.ReadString('\n')
	if err != nil {
		log.Fatal(err)
	}

	response = strings.ToLower(strings.TrimSpace(response))

	if response == "y" || response == "yes" {
		return true
	}
	return false
}
