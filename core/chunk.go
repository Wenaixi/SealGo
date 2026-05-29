package core

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"
)

// SealChunk 使用 AEAD 加密一个数据块，返回密封数据。
// 格式：[4B chunk_len LE][ciphertext + poly1305_tag]
func SealChunk(aead cipher.AEAD, plaintext []byte, base [NonceSize]byte, counter uint64) []byte {
	aad := make([]byte, 4)
	binary.LittleEndian.PutUint32(aad, uint32(len(plaintext)))

	var nonce [NonceSize]byte
	SetNonce(nonce[:], base, counter)

	sealed := aead.Seal(nil, nonce[:], plaintext, aad)

	out := make([]byte, 4+len(sealed))
	binary.LittleEndian.PutUint32(out[:4], uint32(len(plaintext)))
	copy(out[4:], sealed)
	return out
}

// OpenChunk 从密封数据中解密一个 AEAD 块，返回明文。
// sealed 必须以 4 字节 chunk_len 前缀开头。
// 遇到已认证的 EOF 标记时返回 ErrEOF。
func OpenChunk(aead cipher.AEAD, sealed []byte, base [NonceSize]byte, counter uint64) ([]byte, error) {
	if len(sealed) < 4 {
		return nil, fmt.Errorf("chunk too short: %d bytes", len(sealed))
	}
	chunkLen := binary.LittleEndian.Uint32(sealed[:4])

	if chunkLen == 0 {
		eofAAD := [4]byte{0, 0, 0, 0}
		var nonce [NonceSize]byte
		SetNonce(nonce[:], base, counter)
		if _, err := aead.Open(nil, nonce[:], sealed[4:], eofAAD[:]); err != nil {
			return nil, ErrEOFMarkerInvalid
		}
		return nil, ErrEOF
	}

	expectedLen := 4 + int(chunkLen) + aead.Overhead()
	if len(sealed) < expectedLen {
		return nil, fmt.Errorf("chunk truncated: have %d bytes, need %d", len(sealed), expectedLen)
	}

	aad := make([]byte, 4)
	binary.LittleEndian.PutUint32(aad, chunkLen)

	var nonce [NonceSize]byte
	SetNonce(nonce[:], base, counter)

	plaintext, err := aead.Open(nil, nonce[:], sealed[4:expectedLen], aad)
	if err != nil {
		return nil, NewVerificationError(int(counter), ErrAuthFailed)
	}
	return plaintext, nil
}

// SealEOF 创建已认证的 EOF 标记：4 字节 0 + Poly1305 标签。
func SealEOF(aead cipher.AEAD, base [NonceSize]byte, counter uint64) []byte {
	var nonce [NonceSize]byte
	SetNonce(nonce[:], base, counter)
	eofAAD := [4]byte{0, 0, 0, 0}
	tag := aead.Seal(nil, nonce[:], nil, eofAAD[:])
	out := make([]byte, 4+len(tag))
	// 前 4 字节为零（chunk_len = 0 标记 EOF）
	copy(out[4:], tag)
	return out
}