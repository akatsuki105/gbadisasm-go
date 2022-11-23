# gbadisasm-go

A Go version clone of [camthesaxman/gbadisasm](https://github.com/camthesaxman/gbadisasm) (+α).

## Usage

```sh
> make build-windows # macOS: make build-darwin
> ./gbadisgo.exe -c ROM_CONFIG.cfg ROM.gba
```

## Directory mode

Unlike the original, `gbadisasm-go` can split the disassemble output into multiple files.

To do so, you need to specify the output directory and provide a delimiter in the cfg file.

The delimiter is defined using the following `file_begin` directive.

```txt
file_begin ADDRESS FILENAME

e.g.
  file_begin 0x080f35c4 menu
```

And, you have to specify output directory by `-d` option.

For example,

```sh
> ./gbadisgo.exe -d ./asm -c ./test/RockmanZero3/RockmanZero3.cfg ./test/RockmanZero3/RockmanZero3.gba
```

If you run above command, output is

```sh
asm
├── main.s          # disassemble for 0x08000000..
├── menu.s          # disassemble for 0x080f35c4..
├── analysis.s      # disassemble for 0x080f7d70..
├── minigame.s      # disassemble for 0x080f8d20..
└── lib.s           # disassemble for 0x080fc44c..
```

You can use the original `.cfg` with `gbadisasm-go`, and vice versa.
