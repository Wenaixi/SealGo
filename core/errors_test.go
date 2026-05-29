package core

import (
	"errors"
	"testing"
)

func TestErrorSentinels(t *testing.T) {
	tests := []struct {
		err    error
		name  string
		match bool
	}{
		{ErrNotEncryptedFile, "ErrNotEncryptedFile", true},
		{ErrUnsupportedVersion, "ErrUnsupportedVersion", true},
		{ErrInvalidChunkSize, "ErrInvalidChunkSize", true},
		{ErrAuthFailed, "ErrAuthFailed", true},
		{ErrInvalidKey, "ErrInvalidKey", true},
		{ErrUnexpectedEOF, "ErrUnexpectedEOF", true},
		{ErrTruncatedData, "ErrTruncatedData", true},
		{ErrEOFMarkerInvalid, "ErrEOFMarkerInvalid", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.match && !errors.Is(tt.err, tt.err) {
				t.Errorf("errors.Is should match %s", tt.name)
			}
		})
	}
}

func TestVerificationError(t *testing.T) {
	inner := ErrAuthFailed
	ve := &VerificationError{ChunkIndex: 5, inner: inner}

	if ve.Error() != "verification failed at chunk 5: authentication failed - chunk may be corrupted or tampered with" {
		t.Errorf("unexpected error message: %s", ve.Error())
	}

	if !errors.Is(ve, ErrAuthFailed) {
		t.Error("VerificationError should unwrap to ErrAuthFailed")
	}

	if !errors.Is(ve, inner) {
		t.Error("VerificationError should unwrap to inner error")
	}
}

func TestWrapError(t *testing.T) {
	base := ErrAuthFailed

	wrapped := WrapError(base, "decrypt chunk 3")
	if wrapped.Error() != "decrypt chunk 3: authentication failed - chunk may be corrupted or tampered with" {
		t.Errorf("unexpected wrapped message: %s", wrapped.Error())
	}

	if !errors.Is(wrapped, base) {
		t.Error("WrapError should preserve errors.Is behavior")
	}

	// nil should return nil
	if WrapError(nil, "context") != nil {
		t.Error("WrapError(nil) should return nil")
	}
}

func TestWrappedErrorIs(t *testing.T) {
	base := ErrAuthFailed
	wrapped := WrapError(base, "test")

	if !errors.Is(wrapped, ErrAuthFailed) {
		t.Error("wrapped error should match base error")
	}
}