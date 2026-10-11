BINARY := bin/connectsnoop
SERVER_BINARY := bin/httpserver
BPF_OBJ := bpf/connectsnoop.bpf.o
LIFECYCLE_OBJ := bpf/lifecycle.bpf.o
CLANG ?= clang
GOFLAGS ?= -buildvcs=false
GOCACHE ?= /tmp/go-build
GOMODCACHE ?= /tmp/go-mod

.PHONY: build build-bpf test test-integration run run-server clean

build-bpf:
	$(CLANG) -O2 -target bpfel -c bpf/connectsnoop.bpf.c -o $(BPF_OBJ)
	$(CLANG) -O2 -g -Wall -Werror -target bpfel -mcpu=v3 -c bpf/lifecycle.bpf.c -o $(LIFECYCLE_OBJ)

build: build-bpf
	mkdir -p bin
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go build $(GOFLAGS) -o $(BINARY) ./cmd/connectsnoop
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go build $(GOFLAGS) -o $(SERVER_BINARY) ./cmd/httpserver

run: build
	sudo ./$(BINARY) $(ARGS)

run-server: build
	./$(SERVER_BINARY) $(ARGS)

test: build-bpf
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go test ./...

test-integration: build
	sudo env GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) CONNECTSNOOP_INTEGRATION=1 go test -count=1 -v ./cmd/connectsnoop -run TestInboundIntegration

clean:
	rm -rf bin
	rm -f $(BPF_OBJ)
	rm -f $(LIFECYCLE_OBJ)
