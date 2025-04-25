evm:
	go build -buildmode=pie -ldflags "-linkmode external -extldflags -static-pie"
	sudo kraft build .

.PHONY: run
run: evm
	sudo kraft run -p 8080:8080 --memory 2048M .

.PHONY: clean
clean:
	rm ./evm
