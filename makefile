NAME := gbadisgo
VERSION := $(shell git describe --tags 2>/dev/null)
LDFLAGS := -X 'main.version=$(VERSION) -s -w'

.PHONY: build-darwin
build-darwin:
	@GOOS=darwin go build -trimpath -o $(NAME) -ldflags "$(LDFLAGS)" ./main.go

.PHONY: build-linux
build-linux:
	@GOOS=linux go build -trimpath -o $(NAME) -ldflags "$(LDFLAGS)" ./main.go

.PHONY: build-windows
build-windows:
	@GOOS=windows go build -trimpath -o $(NAME).exe -ldflags "$(LDFLAGS)" ./main.go

.PHONY: clean
clean:
	@-rm -rf $(BINDIR)

.PHONY: help
help:
	@make2help $(MAKEFILE_LIST)
