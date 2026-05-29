package stream

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"

	"SealGo/core"
)

// NewEncryptWriterWithRecipients 创建向多个接收者加密的 EncryptWriter。
// 每个接收者的公钥将文件密钥包装为存储在头部中的 stanza。
//
// 参数：
//   - w: 目标写入器
//   - recipients: 接收者公钥列表（至少一个）
//   - chunkSize: 数据块大小（0 = 默认 64 KiB）
//   - salt: 固定盐值（nil = 随机）
//   - password: 预留，v1 中未使用
//   - fileKey: 如果非空，用作文件密钥而非随机生成（hybrid 模式）
func NewEncryptWriterWithRecipients(w io.Writer, recipients []core.Recipient, chunkSize int, salt []byte, password string, fileKey []byte) (*EncryptWriter, error) {
	if len(recipients) == 0 {
		return nil, fmt.Errorf("at least one recipient is required")
	}
	if len(recipients) > 255 {
		return nil, fmt.Errorf("recipient count must be <= 255")
	}

	// 1. 生成或使用提供的文件密钥
	var fk [core.KeySize]byte
	if fileKey != nil {
		if len(fileKey) != core.KeySize {
			return nil, fmt.Errorf("file key must be %d bytes, got %d", core.KeySize, len(fileKey))
		}
		copy(fk[:], fileKey)
	} else {
		if _, err := rand.Read(fk[:]); err != nil {
			return nil, fmt.Errorf("generate file key: %w", err)
		}
	}

	// 2. 从文件密钥派生内容密钥
	contentKey := core.HkdfDerive(fk[:], core.HkdfInfoContent, core.KeySize)

	// 3. 生成盐值
	if salt == nil {
		var err error
		salt, err = randomBytes(core.SaltSize)
		if err != nil {
			return nil, fmt.Errorf("generate salt: %w", err)
		}
	}

	// 4. 生成基础 nonce
	baseNonce, err := randomBytes(core.NonceSize)
	if err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	// 5. 校验 chunkSize
	if chunkSize <= 0 || chunkSize > 16*1024*1024 {
		chunkSize = core.DefaultChunkSize
	}

	// 6. 为每个接收者包装文件密钥
	stanzas := make([]core.RecipientStanza, 0, len(recipients))
	for _, r := range recipients {
		stanza, err := r.Wrap(fk[:])
		if err != nil {
			return nil, fmt.Errorf("wrap for recipient: %w", err)
		}
		stanzas = append(stanzas, stanza)
	}

	// 7. 从内存擦除文件密钥
	core.WipeBytes(fk[:])

	// 8. 构建头部：100 字节固定前缀 + stanzas
	headerLen := 100 + len(stanzas)*core.RecipientStanzaSize
	header := make([]byte, headerLen)
	copy(header[0:4], core.FileMagic)
	header[4] = byte(core.FileVersion)
	header[5] = 0                        // flags（预留）
	header[6] = byte(len(stanzas))       // 接收者数量
	header[7] = 0                        // 预留
	copy(header[8:8+core.SaltSize], salt)
	copy(header[8+core.SaltSize:8+core.SaltSize+core.NonceSize], baseNonce)
	binary.LittleEndian.PutUint32(header[8+core.SaltSize+core.NonceSize:], uint32(chunkSize))
	// 字节 68-99 为预留零

	// 在 100 字节固定前缀后追加 stanzas
	offset := 100
	for _, s := range stanzas {
		binary.LittleEndian.PutUint32(header[offset:], s.Type)
		copy(header[offset+4:], s.EphemeralPubKey[:])
		copy(header[offset+36:], s.EncryptedFileKey[:])
		offset += core.RecipientStanzaSize
	}

	// 9. 写入头部
	if _, err := w.Write(header); err != nil {
		return nil, fmt.Errorf("write header: %w", err)
	}

	// 10. 创建 EncryptWriter
	return newEncryptWriterWithKey(w, contentKey, chunkSize, baseNonce)
}