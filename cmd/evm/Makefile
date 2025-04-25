evm:
	go build -buildmode=pie -ldflags "-linkmode external -extldflags -static-pie"
	sudo ./kraft build .

.PHONY: run
run: evm
	sudo ./kraft run --memory 512M .

.PHONY: clean
clean:
	rm ./evm
