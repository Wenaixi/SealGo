package stream

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"SealGo/core"

	"golang.org/x/crypto/chacha20poly1305"
)

// DecryptReader 包装 io.Reader，从中读取并解密数据。
// 单次使用，只能选择 Read() 或 WriteTo() 之一。
type DecryptReader struct {
	r            io.Reader
	aead         cipher.AEAD
	nonce        [core.NonceSize]byte
	counter      uint64
	plaintextMax uint32
	buf          []byte
	offset       int
	sealedBuf    []byte
	eof          bool
	consumed     bool
}

// newDecryptReaderFromInfo 从已派生的 contentKey 和已解析的 HeaderInfo 创建 DecryptReader。
// 不会调用 ParseHeader。
func newDecryptReaderFromInfo(r io.Reader, contentKey []byte, info *core.HeaderInfo) (*DecryptReader, error) {
	aead, err := chacha20poly1305.NewX(contentKey)
	if err != nil {
		return nil, fmt.Errorf("init cipher: %w", err)
	}

	dr := &DecryptReader{
		r:            r,
		aead:         aead,
		plaintextMax: info.ChunkSize,
	}
	copy(dr.nonce[:16], info.NoncePrefix[:])
	return dr, nil
}

func (dr *DecryptReader) Read(p []byte) (int, error) {
	if dr.consumed && dr.offset >= len(dr.buf) && !dr.eof {
		return 0, errors.New("SealGo: DecryptReader already consumed (mixed Read/WriteTo?)")
	}
	if dr.offset < len(dr.buf) {
		n := copy(p, dr.buf[dr.offset:])
		dr.offset += n
		if dr.offset >= len(dr.buf) {
			core.WipeBytes(dr.buf)
			dr.buf = nil
		}
		return n, nil
	}
	if dr.eof {
		return 0, io.EOF
	}

	var chunkLen uint32
	if err := binary.Read(dr.r, binary.LittleEndian, &chunkLen); err != nil {
		if errors.Is(err, io.EOF) {
			return 0, io.ErrUnexpectedEOF
		}
		return 0, fmt.Errorf("read chunk len: %w", err)
	}

	if chunkLen > dr.plaintextMax {
		return 0, fmt.Errorf("chunk too large: %d > %d", chunkLen, dr.plaintextMax)
	}

	sealedLen := 4 + int(chunkLen) + dr.aead.Overhead()
	// 从池中获取可复用缓冲区，减少内存分配
	if cap(dr.sealedBuf) < sealedLen {
		if dr.sealedBuf != nil {
			BufPool.Put(&dr.sealedBuf)
		}
		bp := BufPool.Get().(*[]byte)
		if cap(*bp) < sealedLen {
			b := make([]byte, sealedLen)
			BufPool.Put(bp)
			dr.sealedBuf = b[:sealedLen]
		} else {
			dr.sealedBuf = (*bp)[:sealedLen]
		}
	} else {
		dr.sealedBuf = dr.sealedBuf[:sealedLen]
	}
	// 为 OpenChunk 预先写入 chunk_len 前缀
	binary.LittleEndian.PutUint32(dr.sealedBuf[:4], chunkLen)
	if _, err := io.ReadFull(dr.r, dr.sealedBuf[4:sealedLen]); err != nil {
		return 0, fmt.Errorf("read chunk data: %w", err)
	}

	chunkNonce := dr.counter
	dr.counter++

	plaintext, err := core.OpenChunk(dr.aead, dr.sealedBuf[:sealedLen], dr.nonce, chunkNonce)
	// OpenChunk 返回的 plaintext 可能与 sealedBuf 共享底层数组（aead.Open 原位置解密）。
	// 在归还池前必须拷贝明文，否则下次 Get 同块数组时会读到旧明文残留。
	var plaintextCopy []byte
	if err == nil {
		plaintextCopy = make([]byte, len(plaintext))
		copy(plaintextCopy, plaintext)
	}
	core.WipeBytes(dr.sealedBuf)
	// 将原始切片保存后置 nil，避免池中指针被后续 nil 赋值污染。
	// pool 持有 &dr.sealedBuf 指针，若先置 nil 再 Put，
	// 下次 Get 会拿到 nil 切片，导致 (*bp)[:sealedLen] panic。
	bufToReturn := dr.sealedBuf
	dr.sealedBuf = nil
	BufPool.Put(&bufToReturn)
	if err != nil {
		if errors.Is(err, core.ErrEOF) {
			dr.eof = true
			return 0, io.EOF
		}
		core.WipeBytes(dr.nonce[:])
		return 0, err
	}

	dr.buf = plaintextCopy
	dr.offset = 0
	n := copy(p, dr.buf)
	dr.offset += n
	return n, nil
}

// WriteTo 实现 io.WriterTo，用于零拷贝大批量写入。
func (dr *DecryptReader) WriteTo(w io.Writer) (n int64, err error) {
	if dr.consumed {
		return 0, errors.New("SealGo: DecryptReader already consumed (mixed Read/WriteTo?)")
	}
	dr.consumed = true

	// 从池中获取临时缓冲区用于批量解密
	bufPtr := BufPool.Get().(*[]byte)
	sealedBuf := *bufPtr
	defer func() {
		core.WipeBytes(sealedBuf)
		BufPool.Put(bufPtr)
	}()

	for {
		var chunkLen uint32
		if err := binary.Read(dr.r, binary.LittleEndian, &chunkLen); err != nil {
			if errors.Is(err, io.EOF) {
				return n, io.ErrUnexpectedEOF
			}
			return n, fmt.Errorf("read chunk len: %w", err)
		}

		if chunkLen > dr.plaintextMax {
			return n, fmt.Errorf("chunk too large: %d > %d", chunkLen, dr.plaintextMax)
		}

		sealedLen := 4 + int(chunkLen) + dr.aead.Overhead()
		if cap(sealedBuf) < sealedLen {
			sealedBuf = make([]byte, sealedLen)
		} else {
			sealedBuf = sealedBuf[:sealedLen]
		}
		binary.LittleEndian.PutUint32(sealedBuf[:4], chunkLen)
		if _, err := io.ReadFull(dr.r, sealedBuf[4:]); err != nil {
			return n, fmt.Errorf("read chunk data: %w", err)
		}

		chunkNonce := dr.counter
		dr.counter++

		plaintext, err := core.OpenChunk(dr.aead, sealedBuf, dr.nonce, chunkNonce)
		if err != nil {
			if errors.Is(err, core.ErrEOF) {
				// 擦除敏感状态后返回
				core.WipeBytes(dr.nonce[:])
				return n, nil
			}
			return n, err
		}

		// plaintext 可能与 sealedBuf 共享底层数组，先写出再擦除。
		nn, writeErr := w.Write(plaintext)
		n += int64(nn)
		core.WipeBytes(sealedBuf)
		if writeErr != nil {
			// 擦除敏感状态后返回
			core.WipeBytes(dr.nonce[:])
			return n, writeErr
		}
	}
}

// Close 实现 io.Closer，擦除内部状态并关闭底层 reader。
func (dr *DecryptReader) Close() error {
	// 擦除敏感状态
	core.WipeBytes(dr.nonce[:])
	if dr.aead != nil {
		// AEAD 无法直接擦除，清理引用
		dr.aead = nil
	}
	// 归还缓冲区到池
	if dr.sealedBuf != nil {
		core.WipeBytes(dr.sealedBuf)
		BufPool.Put(&dr.sealedBuf)
		dr.sealedBuf = nil
	}
	if dr.buf != nil {
		core.WipeBytes(dr.buf)
		dr.buf = nil
	}
	return nil
}