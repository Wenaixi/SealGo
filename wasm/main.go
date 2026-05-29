//go:build js && wasm

package main

import (
	"bytes"
	"encoding/hex"
	"syscall/js"

	"SealGo"
	"SealGo/core"
	"SealGo/stream"
)

var done chan struct{}

func main() {
	js.Global().Set("SealGo", js.ValueOf(map[string]interface{}{
		"generateKeypair": js.FuncOf(generateKeypair),
		"encrypt":         js.FuncOf(encrypt),
		"decrypt":         js.FuncOf(decrypt),
	}))
	<-done
}

func generateKeypair(this js.Value, args []js.Value) interface{} {
	pub, priv, err := SealGo.GenerateKeypair()
	if err != nil {
		return jsError(err)
	}
	return js.ValueOf(map[string]interface{}{
		"public":  hex.EncodeToString(pub[:]),
		"private": hex.EncodeToString(priv[:]),
	})
}

func encrypt(this js.Value, args []js.Value) interface{} {
	if len(args) < 2 {
		return jsErrorStr("encrypt requires (data_hex, recipient_pubkey_hex)")
	}
	data, err := hex.DecodeString(args[0].String())
	if err != nil { return jsError(err) }
	pubBytes, err := hex.DecodeString(args[1].String())
	if err != nil || len(pubBytes) != 32 {
		return jsErrorStr("invalid recipient pubkey")
	}
	var pub [32]byte
	copy(pub[:], pubBytes)
	recip := &core.X25519Recipient{PubKey: pub}
	var encrypted bytes.Buffer
	ew, err := stream.NewEncryptWriterWithRecipients(&encrypted, []core.Recipient{recip}, core.DefaultChunkSize, nil, "", nil)
	if err != nil { return jsError(err) }
	if _, err := ew.Write(data); err != nil { return jsError(err) }
	if err := ew.Close(); err != nil { return jsError(err) }
	return jsString(hex.EncodeToString(encrypted.Bytes()))
}

func decrypt(this js.Value, args []js.Value) interface{} {
	if len(args) < 2 {
		return jsErrorStr("decrypt requires (data_hex, identity_privkey_hex)")
	}
	data, err := hex.DecodeString(args[0].String())
	if err != nil { return jsError(err) }
	privBytes, err := hex.DecodeString(args[1].String())
	if err != nil || len(privBytes) != 32 {
		return jsErrorStr("invalid identity privkey")
	}
	var priv [32]byte
	copy(priv[:], privBytes)
	ident := &core.X25519Identity{PrivKey: priv}
	var decrypted bytes.Buffer
	dr, _, err := stream.NewDecryptReaderWithIdentity(bytes.NewReader(data), []core.Identity{ident})
	if err != nil { return jsError(err) }
	if _, err := dr.WriteTo(&decrypted); err != nil { return jsError(err) }
	return jsString(hex.EncodeToString(decrypted.Bytes()))
}

func jsString(s string) js.Value { return js.ValueOf(s) }
func jsError(err error) js.Value { return js.Global().Get("Error").New(err.Error()) }
func jsErrorStr(s string) js.Value { return js.Global().Get("Error").New(s) }