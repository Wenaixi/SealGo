package core

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/curve25519"
)

const (
	// RecipientTypeX25519 是 X25519 接收者 stanzas 的类型标识。
	RecipientTypeX25519 uint32 = 0x00000001

	// RecipientStanzaSize 是单个接收者 stanza 的线格式大小：
	// type(4) + ephemeral_pub(32) + encrypted_file_key(32) = 68 字节。
	RecipientStanzaSize = 4 + 32 + 32

	// RecipientHKDFInfo 是派生包装密钥的 HKDF info 字符串。
	RecipientHKDFInfo = "SealGo-recipient-v1"

	// RecipientNonceHKDFInfo 是派生 XChaCha20 nonce 的 HKDF info 字符串。
	RecipientNonceHKDFInfo = "SealGo-recipient-nonce-v1"

	// RecipientFileKeySize 是接收者加密使用的随机文件密钥长度。
	RecipientFileKeySize = 32
)

// RecipientStanza 表示文件头部中单个接收者的加密文件密钥。
type RecipientStanza struct {
	Type             uint32
	EphemeralPubKey  [32]byte
	EncryptedFileKey [32]byte
}

// Recipient 将文件密钥封装（加密）给指定接收者。
type Recipient interface {
	Type() uint32
	Wrap(fileKey []byte) (RecipientStanza, error)
}

// Identity 从 stanzas 中解封（解密）文件密钥。
type Identity interface {
	Type() uint32
	Unwrap(stanzas []RecipientStanza) ([]byte, error)
}

// GenerateKeypair 生成一个新的 X25519 密钥对。
// 返回公钥和私钥 [32]byte 值。
func GenerateKeypair() (pubKey, privKey [32]byte, err error) {
	if _, err := rand.Read(privKey[:]); err != nil {
		return [32]byte{}, [32]byte{}, fmt.Errorf("generate keypair: %w", err)
	}
	// 钳制私钥（curve25519 必须）。
	privKey[0] &= 248
	privKey[31] &= 127
	privKey[31] |= 64

	pub, err := curve25519.X25519(privKey[:], curve25519.Basepoint)
	if err != nil {
		return [32]byte{}, [32]byte{}, fmt.Errorf("compute public key: %w", err)
	}
	copy(pubKey[:], pub)
	return pubKey, privKey, nil
}

// X25519Recipient 为 X25519 公钥接收者封装文件密钥。
type X25519Recipient struct {
	PubKey [32]byte
}

func (r *X25519Recipient) Type() uint32 { return RecipientTypeX25519 }

// Wrap 使用 ECDH + HKDF + 原始 XChaCha20 加密 fileKey。
// fileKey 必须为 RecipientFileKeySize（32）字节。
//
// 使用无认证的 XChaCha20 是有意设计的：
// 文件密钥是 32 字节随机数，无结构性冗余，
// 篡改只会导致后续 AEAD 块认证失败，无法恢复任何有用信息。
// 类似 NaCl Box 的 curve25519-xsalsa20-poly1305 也采用相同策略。
func (r *X25519Recipient) Wrap(fileKey []byte) (RecipientStanza, error) {
	if len(fileKey) != RecipientFileKeySize {
		return RecipientStanza{}, fmt.Errorf("file key must be %d bytes, got %d", RecipientFileKeySize, len(fileKey))
	}

	// 1. 生成临时密钥对。
	var ephPriv [32]byte
	if _, err := rand.Read(ephPriv[:]); err != nil {
		return RecipientStanza{}, fmt.Errorf("generate ephemeral key: %w", err)
	}
	// 钳制私钥（curve25519 必须）。
	ephPriv[0] &= 248
	ephPriv[31] &= 127
	ephPriv[31] |= 64

	ephPub, err := curve25519.X25519(ephPriv[:], curve25519.Basepoint)
	if err != nil {
		return RecipientStanza{}, fmt.Errorf("compute ephemeral public: %w", err)
	}

	// 2. ECDH 共享秘密。
	shared, err := curve25519.X25519(ephPriv[:], r.PubKey[:])
	if err != nil {
		return RecipientStanza{}, fmt.Errorf("compute shared secret: %w", err)
	}

	// 3. 从共享秘密派生包装密钥和 nonce。
	wrapKey := HkdfDeriveBytes(shared, []byte(RecipientHKDFInfo), chacha20.KeySize)
	nonceBytes := HkdfDeriveBytes(shared, []byte(RecipientNonceHKDFInfo), 24)
	var nonce [24]byte
	copy(nonce[:], nonceBytes)

	// 4. 使用原始 XChaCha20（无 Poly1305）加密文件密钥。
	cipher, err := chacha20.NewUnauthenticatedCipher(wrapKey, nonce[:])
	if err != nil {
		WipeBytes(ephPriv[:])
		WipeBytes(shared)
		WipeBytes(wrapKey)
		return RecipientStanza{}, fmt.Errorf("init xchacha20: %w", err)
	}

	var stanza RecipientStanza
	stanza.Type = RecipientTypeX25519
	copy(stanza.EphemeralPubKey[:], ephPub)
	cipher.XORKeyStream(stanza.EncryptedFileKey[:], fileKey)

	// 5. 擦除敏感数据。
	WipeBytes(ephPriv[:])
	WipeBytes(shared)
	WipeBytes(wrapKey)

	return stanza, nil
}

// X25519Identity 使用 X25519 私钥解封文件密钥。
type X25519Identity struct {
	PrivKey [32]byte
}

func (i *X25519Identity) Type() uint32 { return RecipientTypeX25519 }

// Unwrap 在 stanzas 中查找匹配此身份的条目并解密文件密钥。
// 成功时返回 RecipientFileKeySize（32）字节，失败时返回 ErrNoMatchingRecipient。
func (i *X25519Identity) Unwrap(stanzas []RecipientStanza) ([]byte, error) {
	for _, stanza := range stanzas {
		if stanza.Type != RecipientTypeX25519 {
			continue
		}

		// 1. ECDH 共享秘密。
		shared, err := curve25519.X25519(i.PrivKey[:], stanza.EphemeralPubKey[:])
		if err != nil {
			continue
		}

		// 2. 派生包装密钥和 nonce。
		wrapKey := HkdfDeriveBytes(shared, []byte(RecipientHKDFInfo), chacha20.KeySize)
		nonceBytes := HkdfDeriveBytes(shared, []byte(RecipientNonceHKDFInfo), 24)
		var nonce [24]byte
		copy(nonce[:], nonceBytes)

		// 3. 使用原始 XChaCha20 解密文件密钥。
		cipher, err := chacha20.NewUnauthenticatedCipher(wrapKey, nonce[:])
		if err != nil {
			WipeBytes(shared)
			WipeBytes(wrapKey)
			continue
		}

		fileKey := make([]byte, RecipientFileKeySize)
		cipher.XORKeyStream(fileKey, stanza.EncryptedFileKey[:])

		// 4. 擦除敏感数据。
		WipeBytes(shared)
		WipeBytes(wrapKey)

		return fileKey, nil
	}
	return nil, ErrNoMatchingRecipient
}