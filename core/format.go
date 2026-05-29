// Package core defines the SealGo file format and provides
// utility functions for working with encrypted chunks at the byte level.
// It has no I/O dependencies — all functions operate on []byte.
package core

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"runtime"
)

const (
	FileMagic = "SC01"

	// FileVersion 是当前文件格式版本号。
	// v1 是基于 X25519 多接收者模型的初始版本
	//（格式断裂变更，不兼容旧版对称密钥格式）。
	// 旧版 v2 对称密钥格式已废弃。
	FileVersion byte = 1

	// FlagPassword 标记文件使用密码派生密钥加密（v1 暂未使用，为未来预留）。
	FlagPassword = 1 << 0

	// KeySize 是 XChaCha20 密钥长度（256 位）。
	KeySize = 32
	// SaltSize 是文件头部中随机盐值的长度。
	SaltSize = 32
	// NonceSize 是 XChaCha20 扩展 nonce 长度。
	NonceSize = 24

	// DefaultChunkSize 是默认数据块大小（64 KiB）。
	DefaultChunkSize = 64 * 1024
)

// HeaderInfo 保存解析后的文件头部字段。
type HeaderInfo struct {
	Version        byte
	Flags          byte
	Salt           [SaltSize]byte
	NoncePrefix    [16]byte
	RecipientCount byte
	ChunkSize      uint32
	Stanzas        []RecipientStanza
}

// ParseHeader 从 r 读取并校验文件头部，返回解析后的头部信息。
func ParseHeader(r io.Reader) (*HeaderInfo, error) {
	header := make([]byte, 100)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}
	if string(header[0:4]) != FileMagic {
		return nil, errors.New("not a SealGo file (bad magic)")
	}
	if header[4] != byte(FileVersion) {
		return nil, fmt.Errorf("unsupported version %d", header[4])
	}
	rc := header[6]
	if rc == 0 {
		return nil, ErrInvalidRecipientCount
	}
	chunkSize := binary.LittleEndian.Uint32(header[64:68])
	if chunkSize == 0 || chunkSize > 16*1024*1024 {
		return nil, fmt.Errorf("invalid chunk size %d", chunkSize)
	}
	totalStanzaBytes := int(rc) * RecipientStanzaSize
	stanzaData := make([]byte, totalStanzaBytes)
	if _, err := io.ReadFull(r, stanzaData); err != nil {
		return nil, fmt.Errorf("read recipient stanzas: %w", err)
	}
	stanzas := make([]RecipientStanza, rc)
	for i := 0; i < int(rc); i++ {
		offset := i * RecipientStanzaSize
		stanzas[i].Type = binary.LittleEndian.Uint32(stanzaData[offset : offset+4])
		copy(stanzas[i].EphemeralPubKey[:], stanzaData[offset+4:offset+4+32])
		copy(stanzas[i].EncryptedFileKey[:], stanzaData[offset+4+32:offset+4+32+32])
	}
	for i := range stanzas {
		if stanzas[i].Type != RecipientTypeX25519 {
			return nil, ErrRecipientTypeUnsupported
		}
	}
	info := &HeaderInfo{
		Version:        header[4],
		Flags:          header[5],
		RecipientCount: rc,
		ChunkSize:      chunkSize,
		Stanzas:        stanzas,
	}
	copy(info.Salt[:], header[8:8+SaltSize])
	copy(info.NoncePrefix[:], header[8+SaltSize:8+SaltSize+16])
	return info, nil
}

// SetNonce 将块 nonce 写入 out：out[0:16] = 随机前缀，out[16:24] = counter（uint64 LE）。
func SetNonce(out []byte, base [NonceSize]byte, counter uint64) {
	copy(out[:16], base[:16])
	binary.LittleEndian.PutUint64(out[16:], counter)
}

// WipeBytes 将字节切片清零，配合 runtime.KeepAlive 防止死存储消除。
func WipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
	if len(b) > 0 {
		runtime.KeepAlive(&b[0])
	}
}