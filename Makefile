# This Makefile is meant to be used by people that do not usually work
# with Go source code. If you know what GOPATH is then you probably
# don't need to bother with make.

.PHONY: geth evm all test lint fmt clean devtools help

GOBIN = ./build/bin
GO ?= latest
GORUN = go run

#? uk: Run geth inside a Unikraft unikernel
uk: geth
	@mkdir -p build/bin/tmp
	kraft build

uk-bench:
	sudo kraft run --log-level debug --log-type basic -p 8545:8545 -p 6060:6060 -p 30303:30303 -p 6061:6061 --memory 8192M --no-check-updates . 2>&1 | grep Served | cut -d" " -f25 | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2};?)?)?[mGK]//g" | python scripts/avg.py

uk-run:
	sudo kraft run --log-level debug --log-type basic -p 8545:8545 -p 6060:6060 -p 30303:30303 -p 6061:6061 --memory 8192M --no-check-updates .

geth-bench:
	./build/bin/geth --dev --rpc.gascap 8000000000 --http --http.addr 0.0.0.0 --http.api eth,net,web3,admin,debug --verbosity 4 --pprof --pprof.addr 0.0.0.0 --pprof.port 6061 --metrics --metrics.addr 0.0.0.0 --metrics.port 6060 2>&1 | grep Served | cut -d" " -f25 | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2};?)?)?[mGK]//g" | python scripts/avg.py

geth-run:
	./build/bin/geth --dev --rpc.gascap 8000000000 --http --http.addr 0.0.0.0 --http.api eth,net,web3,admin,debug --verbosity 4 --pprof --pprof.addr 0.0.0.0 --pprof.port 6061 --metrics --metrics.addr 0.0.0.0 --metrics.port 6060
	   
geth-console:
	./build/bin/geth attach http://127.0.0.1:8545

#? geth: Build geth as a static binary.
geth:
	$(GORUN) build/ci.go install -static ./cmd/geth
	@echo "Done building."
	@echo "Run \"$(GOBIN)/geth\" to launch geth."

#? evm: Build evm.
evm:
	$(GORUN) build/ci.go install ./cmd/evm
	@echo "Done building."
	@echo "Run \"$(GOBIN)/evm\" to launch evm."

#? all: Build all packages and executables.
all:
	$(GORUN) build/ci.go install

#? test: Run the tests.
test: all
	$(GORUN) build/ci.go test

#? lint: Run certain pre-selected linters.
lint: ## Run linters.
	$(GORUN) build/ci.go lint

#? fmt: Ensure consistent code formatting.
fmt:
	gofmt -s -w $(shell find . -name "*.go")

#? clean: Clean go cache, built executables, and the auto generated folder.
clean:
	go clean -cache
	rm -fr build/_workspace/pkg/ $(GOBIN)/*
uk-clean:
	rm -fr build/_workspace/pkg/ $(GOBIN)/*
	rm -fr Makefile.uk
	rm -fr .unikraft
	rm -fr .config*


# The devtools target installs tools required for 'go generate'.
# You need to put $GOBIN (or $GOPATH/bin) in your PATH to use 'go generate'.

#? devtools: Install recommended developer tools.
devtools:
	env GOBIN= go install golang.org/x/tools/cmd/stringer@latest
	env GOBIN= go install github.com/fjl/gencodec@latest
	env GOBIN= go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	env GOBIN= go install ./cmd/abigen
	@type "solc" 2> /dev/null || echo 'Please install solc'
	@type "protoc" 2> /dev/null || echo 'Please install protoc'

#? help: Get more info on make commands.
help: Makefile
	@echo ''
	@echo 'Usage:'
	@echo '  make [target]'
	@echo ''
	@echo 'Targets:'
	@sed -n 's/^#?//p' $< | column -t -s ':' |  sort | sed -e 's/^/ /'
