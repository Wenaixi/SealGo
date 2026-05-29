package stream

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"SealGo/core"

	"golang.org/x/crypto/chacha20poly1305"
)

// NewDecryptReaderWithIdentity 从 r 读取多接收者加密流，尝试每个身份匹配接收者 stanzas，
// 返回解密后的 DecryptReader 和头部信息。
//
// 使用流式试解密：仅将第一个块读入内存进行试解密。
// 找到匹配身份后，其余数据从原始 reader 流式读取，无需完整加载到内存。
func NewDecryptReaderWithIdentity(r io.Reader, identities []core.Identity) (*DecryptReader, *core.HeaderInfo, error) {
	// 1. 解析头部
	info, err := core.ParseHeader(r)
	if err != nil {
		return nil, nil, fmt.Errorf("parse header: %w", err)
	}

	// 2. 尝试身份匹配接收者 stanzas
	if len(info.Stanzas) > 0 {
		if len(identities) == 0 {
			return nil, nil, fmt.Errorf("multi-recipient file requires an identity")
		}

		// 仅读取第一个块用于试解密。
		var chunkLen uint32
		if err := binary.Read(r, binary.LittleEndian, &chunkLen); err != nil {
			return nil, nil, fmt.Errorf("read trial chunk len: %w", err)
		}

		// 防御：chunkLen 上限检查（防止 int 溢出和过大分配）
		// 最大 16MB 与 core/format.go 保持一致
		const maxChunkLen = 16 * 1024 * 1024
		if chunkLen > maxChunkLen || chunkLen > info.ChunkSize {
			return nil, nil, fmt.Errorf("invalid trial chunk length: %d (max %d)", chunkLen, maxChunkLen)
		}

		// 重建 chunkLen 前缀字节（binary.Read 已从 r 消耗 4 字节）。
		sealedLen := 4 + int(chunkLen) + 16 // 16 = Poly1305 开销
		if sealedLen < 4 {
			return nil, nil, fmt.Errorf("invalid trial chunk length: %d", chunkLen)
		}

		trialData := make([]byte, sealedLen)
		binary.LittleEndian.PutUint32(trialData, chunkLen)
		if _, err := io.ReadFull(r, trialData[4:]); err != nil {
			return nil, nil, fmt.Errorf("read trial chunk data: %w", err)
		}

		var fileKey []byte
		for _, id := range identities {
			for _, stanza := range info.Stanzas {
				fk, err := id.Unwrap([]core.RecipientStanza{stanza})
				if err != nil {
					continue
				}
				contentKey := core.HkdfDerive(fk, core.HkdfInfoContent, core.KeySize)
				aead, err := chacha20poly1305.NewX(contentKey)
				if err != nil {
					core.WipeBytes(fk)
					continue
				}

				var trialNonce [core.NonceSize]byte
				copy(trialNonce[:16], info.NoncePrefix[:])

				_, decErr := core.OpenChunk(aead, trialData, trialNonce, 0)
				if decErr != nil && !errors.Is(decErr, core.ErrEOF) {
					core.WipeBytes(fk)
					continue
				}

				fileKey = fk
				break
			}
			if fileKey != nil {
				break
			}
		}
		// 统一返回 ErrNoMatchingRecipient 而非区分"密钥错误"与"无此接收者"，
			// 防止攻击者通过不同错误消息推断文件头部中哪个 stanza 匹配哪个公钥。
			if fileKey == nil {
				return nil, nil, core.ErrNoMatchingRecipient
			}
		defer core.WipeBytes(fileKey)

		// 将试解密的块拼回剩余流，使 DecryptReader 看到完整的块流。
		// 仅第一个块（O(chunkSize)）被缓冲——无需 io.ReadAll。
		contentKey := core.HkdfDerive(fileKey, core.HkdfInfoContent, core.KeySize)
		fullStream := io.MultiReader(bytes.NewReader(trialData), r)
		dr, err := newDecryptReaderFromInfo(fullStream, contentKey, info)
		return dr, info, err
	}

	// 3. 无双接收者 stanzas——返回错误
	return nil, nil, fmt.Errorf("file does not have recipient stanzas")
}