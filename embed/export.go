// Package embed provides C-compatible exports for cross-language use.
//
// Build requires a C compiler (gcc, mingw, or MSVC):
//
//	# Linux / macOS
//	CGO_ENABLED=1 go build -buildmode=c-shared -o libSealGo.so ./embed/
//
//	# Windows (MinGW)
//	CGO_ENABLED=1 GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc \
//	  go build -buildmode=c-shared -o SealGo.dll ./embed/
//
//	# Static archive
//	CGO_ENABLED=1 go build -buildmode=c-archive -o libSealGo.a ./embed/
//
// Usage from C:
//
//	#include "libSealGo.h"
//
//	int main() {
//	    sealgo_keypair kp;
//	    sealgo_generate_keypair(&kp);
//	    // kp.public_hex, kp.private_hex
//
//	    sealgo_result res;
//	    sealgo_encrypt(data_hex, kp.public_hex, &res);
//	    // res.data (hex string), free with sealgo_free_result(&res)
//	}
package main

/*
#include <stdlib.h>
#include <stdint.h>

// Keypair holds hex-encoded X25519 keys (each 64 hex chars + NUL).
typedef struct {
    char* public_hex;   // 65 bytes (64 hex + NUL)
    char* private_hex;  // 65 bytes (64 hex + NUL)
} sealgo_keypair;

// Result holds a hex-encoded output string.
typedef struct {
    char* data;         // hex-encoded output, or NULL on error
    char* error;        // error message, or NULL on success
} sealgo_result;

// Version info.
typedef struct {
    int major;
    int minor;
    int patch;
} sealgo_version;
*/
import "C"

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"unsafe"

	"SealGo"
	"SealGo/core"
	"SealGo/stream"
)

//export sealgo_generate_keypair
func sealgo_generate_keypair(out *C.sealgo_keypair) {
	if out == nil {
		return
	}
	out.public_hex = nil
	out.private_hex = nil

	pub, priv, err := SealGo.GenerateKeypair()
	if err != nil {
		return
	}

	pubHex := C.CString(hex.EncodeToString(pub[:]))
	privHex := C.CString(hex.EncodeToString(priv[:]))
	out.public_hex = pubHex
	out.private_hex = privHex
}

//export sealgo_encrypt
func sealgo_encrypt(dataHex *C.char, recipientPubkeyHex *C.char, out *C.sealgo_result) {
	if out == nil {
		return
	}
	out.data = nil
	out.error = nil

	data, err := hex.DecodeString(C.GoString(dataHex))
	if err != nil {
		out.error = C.CString("invalid data hex: " + err.Error())
		return
	}

	pubBytes, err := hex.DecodeString(C.GoString(recipientPubkeyHex))
	if err != nil || len(pubBytes) != 32 {
		out.error = C.CString("invalid recipient pubkey (expected 32 hex bytes)")
		return
	}

	var pub [32]byte
	copy(pub[:], pubBytes)
	recip := &core.X25519Recipient{PubKey: pub}

	var encrypted bytes.Buffer
	ew, err := stream.NewEncryptWriterWithRecipients(&encrypted, []core.Recipient{recip}, core.DefaultChunkSize, nil, "", nil)
	if err != nil {
		out.error = C.CString(err.Error())
		return
	}
	if _, err := ew.Write(data); err != nil {
		ew.Close()
		out.error = C.CString(err.Error())
		return
	}
	if err := ew.Close(); err != nil {
		out.error = C.CString(err.Error())
		return
	}

	out.data = C.CString(hex.EncodeToString(encrypted.Bytes()))
}

//export sealgo_decrypt
func sealgo_decrypt(dataHex *C.char, identityPrivkeyHex *C.char, out *C.sealgo_result) {
	if out == nil {
		return
	}
	out.data = nil
	out.error = nil

	data, err := hex.DecodeString(C.GoString(dataHex))
	if err != nil {
		out.error = C.CString("invalid data hex: " + err.Error())
		return
	}

	privBytes, err := hex.DecodeString(C.GoString(identityPrivkeyHex))
	if err != nil || len(privBytes) != 32 {
		out.error = C.CString("invalid identity privkey (expected 32 hex bytes)")
		return
	}

	var priv [32]byte
	copy(priv[:], privBytes)
	ident := &core.X25519Identity{PrivKey: priv}

	var decrypted bytes.Buffer
	dr, _, err := stream.NewDecryptReaderWithIdentity(bytes.NewReader(data), []core.Identity{ident})
	if err != nil {
		out.error = C.CString(err.Error())
		return
	}
	if _, err := dr.WriteTo(&decrypted); err != nil {
		dr.Close()
		out.error = C.CString(err.Error())
		return
	}
	if err := dr.Close(); err != nil {
		out.error = C.CString(err.Error())
		return
	}

	out.data = C.CString(hex.EncodeToString(decrypted.Bytes()))
}

//export sealgo_encrypt_file
func sealgo_encrypt_file(inputPath *C.char, outputPath *C.char, recipientPubkeyHex *C.char, out *C.sealgo_result) {
	if out == nil {
		return
	}
	out.data = nil
	out.error = nil

	pubBytes, err := hex.DecodeString(C.GoString(recipientPubkeyHex))
	if err != nil || len(pubBytes) != 32 {
		out.error = C.CString("invalid recipient pubkey (expected 32 hex bytes)")
		return
	}

	var pub [32]byte
	copy(pub[:], pubBytes)
	recip := &core.X25519Recipient{PubKey: pub}

	inPath := C.GoString(inputPath)
	outPath := C.GoString(outputPath)

	outFile, err := os.Create(outPath)
	if err != nil {
		out.error = C.CString("create output: " + err.Error())
		return
	}
	defer outFile.Close()

	inFile, err := os.Open(inPath)
	if err != nil {
		out.error = C.CString("open input: " + err.Error())
		return
	}
	defer inFile.Close()

	if err := SealGo.EncryptWithRecipients(outFile, inFile, []core.Recipient{recip}, nil); err != nil {
		out.error = C.CString(err.Error())
		return
	}
}

//export sealgo_decrypt_file
func sealgo_decrypt_file(inputPath *C.char, outputPath *C.char, identityPrivkeyHex *C.char, out *C.sealgo_result) {
	if out == nil {
		return
	}
	out.data = nil
	out.error = nil

	privBytes, err := hex.DecodeString(C.GoString(identityPrivkeyHex))
	if err != nil || len(privBytes) != 32 {
		out.error = C.CString("invalid identity privkey (expected 32 hex bytes)")
		return
	}

	var priv [32]byte
	copy(priv[:], privBytes)
	ident := &core.X25519Identity{PrivKey: priv}

	inPath := C.GoString(inputPath)
	outPath := C.GoString(outputPath)

	inFile, err := os.Open(inPath)
	if err != nil {
		out.error = C.CString("open input: " + err.Error())
		return
	}
	defer inFile.Close()

	outFile, err := os.Create(outPath)
	if err != nil {
		out.error = C.CString("create output: " + err.Error())
		return
	}
	defer outFile.Close()

	if err := SealGo.DecryptWithIdentity(outFile, inFile, []core.Identity{ident}); err != nil {
		out.error = C.CString(err.Error())
		return
	}
}

//export sealgo_inspect
func sealgo_inspect(dataHex *C.char, out *C.sealgo_result) {
	if out == nil {
		return
	}
	out.data = nil
	out.error = nil

	data, err := hex.DecodeString(C.GoString(dataHex))
	if err != nil {
		out.error = C.CString("invalid hex: " + err.Error())
		return
	}

	info, err := core.ParseHeader(bytes.NewReader(data))
	if err != nil {
		out.error = C.CString(err.Error())
		return
	}

	// Format as simple text: version, flags, chunk_size, recipient_count
	desc := fmt.Sprintf("version=%d flags=%d chunk_size=%d recipients=%d",
		info.Version, info.Flags, info.ChunkSize, info.RecipientCount)
	out.data = C.CString(desc)
}

//export sealgo_version_string
func sealgo_version_string() *C.char {
	return C.CString(core.Creator())
}

//export sealgo_free_keypair
func sealgo_free_keypair(kp *C.sealgo_keypair) {
	if kp == nil {
		return
	}
	if kp.public_hex != nil {
		C.free(unsafe.Pointer(kp.public_hex))
	}
	if kp.private_hex != nil {
		C.free(unsafe.Pointer(kp.private_hex))
	}
	kp.public_hex = nil
	kp.private_hex = nil
}

//export sealgo_free_result
func sealgo_free_result(res *C.sealgo_result) {
	if res == nil {
		return
	}
	if res.data != nil {
		C.free(unsafe.Pointer(res.data))
	}
	if res.error != nil {
		C.free(unsafe.Pointer(res.error))
	}
	res.data = nil
	res.error = nil
}

//export sealgo_wipe_bytes
func sealgo_wipe_bytes(ptr unsafe.Pointer, length C.int) {
	if ptr == nil || length <= 0 {
		return
	}
	b := unsafe.Slice((*byte)(ptr), int(length))
	core.WipeBytes(b)
}

func main() {}