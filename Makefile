BINARY := bin/connectsnoop
BPF_OBJ := bpf/connectsnoop.bpf.o
GOFLAGS ?= -buildvcs=false
GOCACHE ?= /tmp/go-build
GOMODCACHE ?= /tmp/go-mod

.PHONY: build build-bpf run clean

build-bpf:
	clang -O2 -target bpf -c bpf/connectsnoop.bpf.c -o $(BPF_OBJ)

build: build-bpf
	mkdir -p bin
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go build $(GOFLAGS) -o $(BINARY) ./cmd/connectsnoop

run: build
	sudo ./$(BINARY) $(BPF_OBJ)

clean:
	rm -rf bin
	rm -f $(BPF_OBJ)
