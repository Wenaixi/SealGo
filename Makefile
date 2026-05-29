.PHONY: all cli cli-all wasm docker test clean bench clib clib-all npm pypi formula bucket

GOOS   ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)
VERSION ?= 0.1.1
LDFLAGS = -ldflags="-s -w -X main.Version=$(VERSION) -X core.Version=$(VERSION)" -trimpath

all: cli

# ── Homebrew Formula ───────────────────────────────
formula:
	sed -i 's/#__VERSION__/$(VERSION)/g' Formula/sealgo.rb

# ── Scoop Bucket ────────────────────────────────
bucket:
	sed -i 's/$$version/$(VERSION)/g' bucket/sealgo.json

# ── native CLI ──────────────────────────────────────────
cli:
	CGO_ENABLED=0 go build $(LDFLAGS) -o SealGo ./cmd/cli/

# ── cross-compile ───────────────────────────────────────
cli-all:
	GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 go build $(LDFLAGS) -o dist/SealGo-linux-amd64   ./cmd/cli/
	GOOS=linux   GOARCH=arm64 CGO_ENABLED=0 go build $(LDFLAGS) -o dist/SealGo-linux-arm64   ./cmd/cli/
	GOOS=linux   GOARCH=arm   CGO_ENABLED=0 go build $(LDFLAGS) -o dist/SealGo-linux-arm     ./cmd/cli/
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build $(LDFLAGS) -o dist/SealGo-windows-amd64.exe ./cmd/cli/
	GOOS=darwin  GOARCH=amd64 CGO_ENABLED=0 go build $(LDFLAGS) -o dist/SealGo-darwin-amd64  ./cmd/cli/
	GOOS=darwin  GOARCH=arm64 CGO_ENABLED=0 go build $(LDFLAGS) -o dist/SealGo-darwin-arm64  ./cmd/cli/

# ── WASM ────────────────────────────────────────────────
wasm:
	GOOS=js GOARCH=wasm go build $(LDFLAGS) -o dist/SealGo.wasm ./wasm/
	cp "$(shell go env GOROOT)/lib/wasm/wasm_exec.js" dist/
	cp wasm/bridge.js dist/

# ── C shared library (requires C compiler) ──────────────
clib:
	sed -i 's/__VERSION__/$(VERSION)/g' embed/libSealGo.h
	CGO_ENABLED=1 go build $(LDFLAGS) -buildmode=c-shared -o libSealGo.so ./embed/

clib-static:
	CGO_ENABLED=1 go build $(LDFLAGS) -buildmode=c-archive -o libSealGo.a ./embed/

clib-all:
	CGO_ENABLED=1 GOOS=linux   GOARCH=amd64 go build $(LDFLAGS) -buildmode=c-shared -o dist/libSealGo-linux-amd64.so   ./embed/
	CGO_ENABLED=1 GOOS=linux   GOARCH=arm64 go build $(LDFLAGS) -buildmode=c-shared -o dist/libSealGo-linux-arm64.so   ./embed/
	CGO_ENABLED=1 GOOS=linux   GOARCH=arm   go build $(LDFLAGS) -buildmode=c-shared -o dist/libSealGo-linux-arm.so     ./embed/
	CGO_ENABLED=1 GOOS=darwin  GOARCH=amd64 go build $(LDFLAGS) -buildmode=c-shared -o dist/libSealGo-darwin-amd64.dylib ./embed/
	CGO_ENABLED=1 GOOS=darwin  GOARCH=arm64 go build $(LDFLAGS) -buildmode=c-shared -o dist/libSealGo-darwin-arm64.dylib ./embed/
	# Windows DLL requires MinGW cross-compiler (CC=x86_64-w64-mingw32-gcc)
	CGO_ENABLED=1 GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc \
	  go build $(LDFLAGS) -buildmode=c-shared -o dist/SealGo-windows-amd64.dll ./embed/

# ── npm package ──────────────────────────────────────────
npm: wasm
	sed -i 's/"version": "[^"]*"/"version": "$(VERSION)"/' npm/package.json
	mkdir -p npm
	cp dist/SealGo.wasm npm/
	cp "$(shell go env GOROOT)/lib/wasm/wasm_exec.js" npm/
	cp wasm/bridge.js npm/

# ── Python package ──────────────────────────────────────
pypi:
	sed -i 's/version="[^"]*"/version="$(VERSION)"/' pystreamcrypt/setup.py
	mkdir -p pystreamcrypt/src/sealgo/
	cp dist/SealGo-$(GOOS)-$(GOARCH)$(if $(filter windows,$(GOOS)),.exe,) pystreamcrypt/src/sealgo/SealGo$(if $(filter windows,$(GOOS)),.exe,)

# ── Docker ──────────────────────────────────────────────
docker:
	docker build -f docker/Dockerfile -t SealGo:latest .

# ── test ───────────────────────────────────────────────
test:
	go test -v -count=1 -race ./...

# ── benchmark ───────────────────────────────────────────
bench:
	go test -bench=. -benchmem ./...

# ── clean ───────────────────────────────────────────────
clean:
	rm -f SealGo
	rm -rf dist/
	rm -f libSealGo.so libSealGo.a
	rm -f pystreamcrypt/src/sealgo/*.so