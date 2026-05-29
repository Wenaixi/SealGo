// Package SealGo provides streaming encryption/decryption using XChaCha20-Poly1305.
//
// # Architecture
//
//	embed/     C-shared exports for C/C++/Python/Rust (cgo)
//	cmd/cli/   Single-file CLI tool
//	wasm/      Browser WASM entry point
//	core/      Pure format definition + byte-level chunk crypto (zero I/O)
//	stream/    io.Reader/Writer wrappers ("everything is a stream")
package SealGo

import (
	"fmt"
	"io"

	"SealGo/core"
	"SealGo/stream"

	"golang.org/x/sys/cpu"
)

// 重新导出的常量。
const (
	KeySize             = core.KeySize
	SaltSize            = core.SaltSize
	NonceSize           = core.NonceSize
	DefaultChunkSize    = core.DefaultChunkSize
	RecipientTypeX25519 = core.RecipientTypeX25519
	RecipientStanzaSize = core.RecipientStanzaSize
)

// WipeBytes 将字节切片清零。
func WipeBytes(b []byte) { core.WipeBytes(b) }

// SetNonce 写入块 nonce。
func SetNonce(out []byte, base [core.NonceSize]byte, counter uint64) {
	core.SetNonce(out, base, counter)
}

// 重新导出的类型。
type (
	HeaderInfo      = core.HeaderInfo
	Recipient       = core.Recipient
	Identity        = core.Identity
	RecipientStanza = core.RecipientStanza
	X25519Recipient = core.X25519Recipient
	X25519Identity  = core.X25519Identity
)

// ParseHeader 读取并校验文件头部。
func ParseHeader(r io.Reader) (*core.HeaderInfo, error) {
	return core.ParseHeader(r)
}

// GenerateKeypair 生成新的 X25519 密钥对。
func GenerateKeypair() (pubKey, privKey [32]byte, err error) {
	return core.GenerateKeypair()
}

// EncryptWithRecipients 将数据加密给多个接收者。
// 如果 fileKey 非空，则用作文件密钥而非随机生成（hybrid -r + -k 模式）。
func EncryptWithRecipients(w io.Writer, r io.Reader, recipients []core.Recipient, fileKey []byte) error {
	ew, err := stream.NewEncryptWriterWithRecipients(w, recipients, core.DefaultChunkSize, nil, "", fileKey)
	if err != nil {
		return err
	}
	if _, err := io.Copy(ew, r); err != nil {
		ew.Close()
		return fmt.Errorf("encrypt: %w", err)
	}
	return ew.Close()
}

// DecryptWithIdentity 使用提供的身份解密多接收者文件。
func DecryptWithIdentity(w io.Writer, r io.Reader, identities []core.Identity) error {
	dr, _, err := stream.NewDecryptReaderWithIdentity(r, identities)
	if err != nil {
		return err
	}
	_, err = io.Copy(w, dr)
	return err
}

// NewEncryptWriterWithRecipients 创建用于多接收者加密的 EncryptWriter。
func NewEncryptWriterWithRecipients(w io.Writer, recipients []core.Recipient, fileKey []byte) (*stream.EncryptWriter, error) {
	return stream.NewEncryptWriterWithRecipients(w, recipients, core.DefaultChunkSize, nil, "", fileKey)
}

// NewDecryptReaderWithIdentity 创建用于多接收者解密的 DecryptReader。
func NewDecryptReaderWithIdentity(r io.Reader, identities []core.Identity) (*stream.DecryptReader, *core.HeaderInfo, error) {
	return stream.NewDecryptReaderWithIdentity(r, identities)
}

// Inspect 读取并返回文件头部，无需解密密钥。
func Inspect(r io.Reader) (*core.HeaderInfo, error) {
	return core.ParseHeader(r)
}

func init() {
	CPUFeatures.AES = cpu.X86.HasAES || cpu.ARM64.HasAES
	CPUFeatures.AVX2 = cpu.X86.HasAVX2
	CPUFeatures.NEON = cpu.ARM64.HasASIMD
	CPUFeatures.HasHardwareCrypto = CPUFeatures.AES || cpu.ARM64.HasPMULL
}

// CPUFeatures 报告硬件加速能力。
var CPUFeatures = struct {
	AES               bool
	AVX2              bool
	NEON              bool
	HasHardwareCrypto bool
}{}