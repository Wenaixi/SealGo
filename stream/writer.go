package stream

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"SealGo/core"

	"golang.org/x/crypto/chacha20poly1305"
)

// EncryptWriter 包装 io.Writer，写入的数据会被加密后再写入底层流。
type EncryptWriter struct {
	w       io.Writer
	aead    cipher.AEAD
	nonce  [core.NonceSize]byte
	counter uint64
	chunkSz int
	buf    []byte
	bufPtr *[]byte  // 从池获取的缓冲区指针，Close 时归还
	closed   bool
	writeErr error
}

// newEncryptWriterWithKey 从已派生的内容密钥创建 EncryptWriter。
// 不会写入头部——调用方负责在调用前写入正确的头部格式。
func newEncryptWriterWithKey(w io.Writer, contentKey []byte, chunkSize int, baseNonce []byte) (*EncryptWriter, error) {
	aead, err := chacha20poly1305.NewX(contentKey)
	if err != nil {
		return nil, fmt.Errorf("init cipher: %w", err)
	}

	ew := &EncryptWriter{
		w:      w,
		aead:   aead,
		chunkSz: chunkSize,
	}

	// 从池获取缓冲区，避免构造时分配
	bufPtr := BufPool.Get().(*[]byte)
	ew.buf = (*bufPtr)[:0]
	ew.bufPtr = bufPtr
	copy(ew.nonce[:16], baseNonce[:16])
	return ew, nil
}

func (ew *EncryptWriter) Write(p []byte) (int, error) {
	if ew.closed {
		return 0, fmt.Errorf("encrypt writer is closed")
	}
	if ew.writeErr != nil {
		return 0, ew.writeErr
	}

	total := 0
	for len(p) > 0 {
		space := ew.chunkSz - len(ew.buf)
		n := min(space, len(p))
		ew.buf = append(ew.buf, p[:n]...)
		p = p[n:]
		total += n

		if len(ew.buf) >= ew.chunkSz {
			if err := ew.flush(); err != nil {
				ew.writeErr = err
				return total, err
			}
		}
	}
	return total, nil
}

func (ew *EncryptWriter) Close() error {
	if ew.closed {
		return nil
	}
	ew.closed = true

	if len(ew.buf) > 0 {
		if err := ew.flush(); err != nil {
			return err
		}
	}

	eof := core.SealEOF(ew.aead, ew.nonce, ew.counter)
	if _, err := ew.w.Write(eof); err != nil {
		return fmt.Errorf("write eof: %w", err)
	}

	core.WipeBytes(ew.buf)
	core.WipeBytes(ew.nonce[:])
	// 归还缓冲区到池
	if ew.bufPtr != nil {
		BufPool.Put(ew.bufPtr)
		ew.bufPtr = nil
	}
	return nil
}

func (ew *EncryptWriter) flush() error {
	if len(ew.buf) == 0 {
		return nil
	}
	sealed := core.SealChunk(ew.aead, ew.buf, ew.nonce, ew.counter)
	ew.counter++
	if _, err := ew.w.Write(sealed); err != nil {
		return fmt.Errorf("write chunk: %w", err)
	}
	core.WipeBytes(ew.buf)
	ew.buf = ew.buf[:0]
	return nil
}

// ReadFrom 实现 io.ReaderFrom，用于零拷贝大批量读取。
func (ew *EncryptWriter) ReadFrom(r io.Reader) (n int64, err error) {
	if ew.closed {
		return 0, fmt.Errorf("encrypt writer is closed")
	}
	if ew.writeErr != nil {
		return 0, ew.writeErr
	}
	// 从池中获取临时缓冲区用于批量读取加密
	bufPtr := BufPool.Get().(*[]byte)
	buf := *bufPtr
	buf = buf[:ew.chunkSz]
	defer func() {
		core.WipeBytes(buf)
		BufPool.Put(bufPtr)
	}()
	for {
		nn, readErr := io.ReadFull(r, buf)
		if nn > 0 {
			if _, writeErr := ew.Write(buf[:nn]); writeErr != nil {
				return n, writeErr
			}
			n += int64(nn)
		}
		if readErr != nil {
			if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
				return n, nil
			}
			return n, readErr
		}
	}
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}