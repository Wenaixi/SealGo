# sealgo-wasm

XChaCha20-Poly1305 streaming encryption for the browser (WASM).

```
npm install sealgo-wasm
```

## Usage

```js
import SealGo from 'sealgo-wasm';

// 1. Initialize (fetches and instantiates the WASM binary)
await SealGo.init();

// 2. Generate a keypair
const kp = SealGo.generateKeypair();
// kp.public  — hex-encoded X25519 public key (64 hex chars)
// kp.private — hex-encoded X25519 private key (64 hex chars)

// 3. Encrypt
const encrypted = SealGo.encrypt(dataHex, kp.public);
// dataHex: hex-encoded plaintext
// returns: hex-encoded ciphertext

// 4. Decrypt
const decrypted = SealGo.decrypt(encrypted, kp.private);
// returns: hex-encoded plaintext
```

## API

### `SealGo.init(wasmUrl?)`

Initialize the WASM module. If `wasmUrl` is provided, fetches the WASM binary from the given URL; otherwise resolves `SealGo.wasm` relative to this module.

Returns a Promise that resolves when ready.

### `SealGo.generateKeypair()`

Generate a new X25519 keypair.

Returns `{ public: string, private: string }` — both hex-encoded 32-byte keys (64 hex chars each).

### `SealGo.encrypt(dataHex, recipientPubkeyHex)`

Encrypt hex-encoded data to a recipient's public key.

- `dataHex` — hex-encoded plaintext
- `recipientPubkeyHex` — hex-encoded X25519 public key

Returns the hex-encoded ciphertext, or throws an `Error` on failure.

### `SealGo.decrypt(dataHex, identityPrivkeyHex)`

Decrypt hex-encoded data with an identity private key.

- `dataHex` — hex-encoded ciphertext
- `identityPrivkeyHex` — hex-encoded X25519 private key

Returns the hex-encoded plaintext, or throws an `Error` on failure.

## Build

```bash
make npm
```

This produces `npm/SealGo.wasm`, `npm/wasm_exec.js`, `npm/bridge.js`, and `npm/index.js`.

## License

MIT