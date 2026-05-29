# SealGo

**XChaCha20-Poly1305 streaming encryption for low-power devices.**

One codebase. Every target.

```
SealGo genpair
SealGo encrypt -r <pubkey> -i secrets.dat -o secrets.sc
SealGo decrypt -I <privkey> -i secrets.sc -o secrets.dat
```

## Features

- **XChaCha20-Poly1305** — authenticated encryption, 3-5x faster than AES-GCM on ARM
- **Argon2id** — password-based key derivation, memory-hard
- **Streaming** — O(1) memory, handles files of any size
- **Poly1305 auth** — detects tampering per chunk
- **Cross-platform** — Linux, macOS, Windows, ARM
- **WASM** — runs in the browser
- **Docker** — 8MB distroless image

## Install

```bash
# Build from source
git clone ... && cd SealGo
make cli
sudo cp SealGo /usr/local/bin/

# Cross-compile all targets
make cli-all    # → dist/
make wasm       # → dist/SealGo.wasm + JS bridge
make docker     # → SealGo:latest
```

## Usage

### Key Generation

```bash
SealGo genpair                    # prints hex public + private key
```

### Encrypt

```bash
# With recipient public key
SealGo encrypt -r <pubkey_hex> -i data.bin -o data.sc

# Pipe mode
cat data.bin | SealGo encrypt -r <pubkey_hex> > data.sc
```

### Decrypt

```bash
SealGo decrypt -I <privkey_hex> -i data.sc -o data.bin
```

### Docker

```bash
docker run --rm -v $(pwd):/data SealGo encrypt -r <pubkey> -i /data/in -o /data/out
```

### Browser (WASM)

```html
<script src="wasm_exec.js"></script>
<script src="bridge.js"></script>
<script>
  await SealGo.init();
  const kp = SealGo.generateKeypair();
  const encrypted = SealGo.encrypt(dataHex, kp.public);
</script>
```

### Go Library

```go
import "SealGo"

pub, priv, _ := SealGo.GenerateKeypair()
// ... encrypt with pub, decrypt with priv
```

## File Format

```
[4B magic "SC01"][1B version][1B flags][2B reserved]
[32B salt][24B base_nonce][4B chunk_size]
[N × 68B recipient stanzas]
[4B chunk_len][N B sealed_data]...
[4B 0x00000000] — EOF sentinel
```

Each chunk is independently encrypted with a counter-derived nonce.

## Performance

| Platform | Throughput | Memory |
|----------|-----------|--------|
| ARM Cortex-A53 (RPi 3) | ~100 MB/s | ~64KB |
| x86_64 (any 2015+) | >500 MB/s | ~64KB |
| WASM (Chrome V8) | ~30 MB/s | ~64KB |

## Security

- No temporary files — everything in memory
- Memory zeroing after use
- Authenticated per chunk (Poly1305)
- Argon2id: 64MB memory, 3 iterations (tunable)
- XChaCha20 nonce: random prefix + counter (no reuse)

## License

MIT
