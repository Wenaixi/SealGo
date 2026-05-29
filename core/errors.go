package core

import (
	"errors"
	"fmt"
)

// SealGo 错误变量，用于精确的错误判断。
var (
	ErrNotEncryptedFile    = errors.New("not a SealGo encrypted file")
	ErrUnsupportedVersion  = errors.New("unsupported file version")
	ErrInvalidChunkSize    = errors.New("invalid chunk size")
	ErrAuthFailed          = errors.New("authentication failed - chunk may be corrupted or tampered with")
	ErrInvalidKey          = errors.New("invalid key length")
	ErrUnexpectedEOF       = errors.New("unexpected end of encrypted stream")
	ErrTruncatedData       = errors.New("encrypted data was truncated")
	ErrEOFMarkerInvalid    = errors.New("invalid EOF marker")
	ErrNoMatchingRecipient = errors.New("no matching recipient stanza found")
	ErrRecipientTypeUnsupported = errors.New("unsupported recipient type")
	ErrInvalidRecipientCount    = errors.New("recipient count must be 1-255")
	ErrEOF                  = errors.New("authenticated eof")
	ErrChunkTooShort        = errors.New("chunk too short")
)

// VerificationError 携带认证失败时所在 chunk 索引，用于定位损坏位置。
// 通过 Unwrap 提供 errors.Is 匹配内部错误，无需自定义 Is 方法。
type VerificationError struct {
	ChunkIndex int
	inner      error
}

// NewVerificationError 创建带指定 chunk 索引和原因的 VerificationError。
func NewVerificationError(chunkIndex int, cause error) error {
	return &VerificationError{ChunkIndex: chunkIndex, inner: cause}
}

func (e *VerificationError) Error() string {
	return fmt.Sprintf("verification failed at chunk %d: %v", e.ChunkIndex, e.inner)
}

func (e *VerificationError) Unwrap() error {
	return e.inner
}

// WrapError 为错误添加额外上下文，保留 errors.Is 对哨兵错误的匹配行为。
func WrapError(err error, context string) error {
	if err == nil {
		return nil
	}
	return &wrappedError{context: context, inner: err}
}

type wrappedError struct {
	context string
	inner   error
}

func (e *wrappedError) Error() string {
	if e.context != "" {
		return e.context + ": " + e.inner.Error()
	}
	return e.inner.Error()
}

func (e *wrappedError) Unwrap() error {
	return e.inner
}

func (e *wrappedError) Is(target error) bool {
	// 递归检查整个错误链
	for err := error(e.inner); err != nil; err = errors.Unwrap(err) {
		if err == target {
			return true
		}
	}
	return false
}