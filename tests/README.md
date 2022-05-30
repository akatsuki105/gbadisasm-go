# `/tests`

Tests need GBA Rom data and original `gbadisasm` binary.

## `gbadisasm`

Please set [gbadisasm](https://github.com/camthesaxman/gbadisasm/tree/e35982bd105fd8b9bb497d955900f8375cdc9e60) on `tests` directory.

```
./tests
├── HelloWorld
├── ...
└── gbadisasm
```

https://github.com/camthesaxman/gbadisasm/tree/e35982bd105fd8b9bb497d955900f8375cdc9e60

`sha1: a9926bae59b704b67fd8fc107eae41908bbece97`

## Usage

```sh
$ go run ./tests TEST_NAME # Test name equals to directory name. e.g. RockmanZero3
```
