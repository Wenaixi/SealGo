package core

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"
	"strings"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestParseHeader(t *testing.T) {
	// Create a header with 2 recipient stanzas
	header := make([]byte, 100+2*RecipientStanzaSize)
	copy(header[0:4], FileMagic)
	header[4] = FileVersion
	header[5] = 0
	header[6] = 2 // recipient count
	header[7] = 0 // reserved
	copy(header[8:8+SaltSize], bytes.Repeat([]byte{0xEE}, SaltSize))
	copy(header[8+SaltSize:8+SaltSize+NonceSize], bytes.Repeat([]byte{0xFF}, NonceSize))
	binary.LittleEndian.PutUint32(header[64:68], DefaultChunkSize)
	// Fill stanzas
	for i := 0; i < 2; i++ {
		off := 100 + i*RecipientStanzaSize
		binary.LittleEndian.PutUint32(header[off:], RecipientTypeX25519)
		copy(header[off+4:off+36], bytes.Repeat([]byte{byte(0x10 + i)}, 32))
		copy(header[off+36:off+68], bytes.Repeat([]byte{byte(0x20 + i)}, 32))
	}

	info, err := ParseHeader(bytes.NewReader(header))
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	if info.Version != FileVersion {
		t.Errorf("version = %d, want %d", info.Version, FileVersion)
	}
	if info.RecipientCount != 2 {
		t.Errorf("recipient count = %d, want 2", info.RecipientCount)
	}
	if len(info.Stanzas) != 2 {
		t.Fatalf("got %d stanzas, want 2", len(info.Stanzas))
	}
	if info.Stanzas[0].Type != RecipientTypeX25519 {
		t.Errorf("stanza[0].Type = %d, want %d", info.Stanzas[0].Type, RecipientTypeX25519)
	}
}

func TestParseHeaderInvalidRecipientCount(t *testing.T) {
	header := make([]byte, 100)
	copy(header[0:4], FileMagic)
	header[4] = FileVersion
	header[6] = 0 // zero recipient count

	_, err := ParseHeader(bytes.NewReader(header))
	if err == nil {
		t.Fatal("expected error for zero recipient count")
	}
}

func TestParseHeaderUnsupportedRecipientType(t *testing.T) {
	header := make([]byte, 100+RecipientStanzaSize)
	copy(header[0:4], FileMagic)
	header[4] = FileVersion
	header[5] = 0
	header[6] = 1
	binary.LittleEndian.PutUint32(header[64:68], DefaultChunkSize)
	binary.LittleEndian.PutUint32(header[100:], 0xDEADBEEF) // unsupported type

	_, err := ParseHeader(bytes.NewReader(header))
	if err == nil || !strings.Contains(err.Error(), "unsupported recipient type") {
		t.Fatalf("expected unsupported recipient type error, got: %v", err)
	}
}

func TestParseHeaderBadMagic(t *testing.T) {
	// Version byte 'X' = 88, not a valid version
	r := bytes.NewReader(append([]byte("XXXX"), 0x00))
	_, err := ParseHeader(r)
	if err == nil {
		t.Fatal("expected error for bad magic")
	}
}

func TestParseHeaderUnsupportedVersion(t *testing.T) {
	header := make([]byte, 8)
	copy(header[0:4], FileMagic)
	header[4] = 99
	_, err := ParseHeader(bytes.NewReader(header))
	if err == nil {
		t.Fatal("expected error for unsupported version")
	}
}

func TestParseHeaderTruncated(t *testing.T) {
	_, err := ParseHeader(bytes.NewReader([]byte("SC0")))
	if err == nil {
		t.Fatal("expected error for truncated header")
	}
}

func TestParseHeaderInvalidChunkSize(t *testing.T) {
	header := make([]byte, 100)
	copy(header[0:4], FileMagic)
	header[4] = FileVersion
	header[6] = 1
	binary.LittleEndian.PutUint32(header[64:68], 0) // zero chunk size

	_, err := ParseHeader(bytes.NewReader(header))
	if err == nil || !strings.Contains(err.Error(), "invalid chunk size") {
		t.Fatalf("expected invalid chunk size error, got: %v", err)
	}
}

func TestParseHeaderChunkSizeTooLarge(t *testing.T) {
	header := make([]byte, 100)
	copy(header[0:4], FileMagic)
	header[4] = FileVersion
	header[6] = 1
	binary.LittleEndian.PutUint32(header[64:68], 16*1024*1024+1)

	_, err := ParseHeader(bytes.NewReader(header))
	if err == nil || !strings.Contains(err.Error(), "invalid chunk size") {
		t.Fatalf("expected invalid chunk size error, got: %v", err)
	}
}

func TestSetNonce(t *testing.T) {
	var base [NonceSize]byte
	for i := 0; i < NonceSize; i++ {
		base[i] = byte(i)
	}
	var out [NonceSize]byte
	SetNonce(out[:], base, 0x0102030405060708)

	// First 16 bytes should match prefix
	for i := 0; i < 16; i++ {
		if out[i] != base[i] {
			t.Errorf("out[%d] = %d, want %d", i, out[i], base[i])
		}
	}
	// Last 8 bytes should be counter LE
	counter := binary.LittleEndian.Uint64(out[16:])
	if counter != 0x0102030405060708 {
		t.Errorf("counter = %d, want %d", counter, 0x0102030405060708)
	}
}

func TestWipeBytes(t *testing.T) {
	b := []byte{1, 2, 3, 4, 5}
	WipeBytes(b)
	for i, v := range b {
		if v != 0 {
			t.Errorf("b[%d] = %d, want 0", i, v)
		}
	}
	// Empty slice should not panic
	WipeBytes(nil)
}

// Test that ParseHeader rejects invalid recipient count in first byte after header
func TestParseHeaderTruncatedStanzas(t *testing.T) {
	header := make([]byte, 100)
	copy(header[0:4], FileMagic)
	header[4] = FileVersion
	header[6] = 10 // claims 10 recipients but no stanza data follows

	_, err := ParseHeader(bytes.NewReader(header))
	if err == nil {
		t.Fatal("expected error for truncated stanzas")
	}
}

func TestSealAndOpenChunk(t *testing.T) {
	key := make([]byte, KeySize)
	rand.Read(key)
	aead := newXChaCha20(t, key)

	var base [NonceSize]byte
	rand.Read(base[:])

	plaintext := []byte("hello chunk test")
	sealed := SealChunk(aead, plaintext, base, 0)

	result, err := OpenChunk(aead, sealed, base, 0)
	if err != nil {
		t.Fatalf("OpenChunk: %v", err)
	}
	if !bytes.Equal(result, plaintext) {
		t.Errorf("got %q, want %q", result, plaintext)
	}
}

func TestOpenChunkEOF(t *testing.T) {
	key := make([]byte, KeySize)
	rand.Read(key)
	aead := newXChaCha20(t, key)

	var base [NonceSize]byte
	rand.Read(base[:])

	eof := SealEOF(aead, base, 0)
	_, err := OpenChunk(aead, eof, base, 0)
	if err != ErrEOF {
		t.Fatalf("expected ErrEOF, got: %v", err)
	}
}

func TestOpenChunkEOFMarkerInvalid(t *testing.T) {
	key := make([]byte, KeySize)
	rand.Read(key)
	aead := newXChaCha20(t, key)

	var base [NonceSize]byte
	rand.Read(base[:])

	// Create EOF with wrong key
	key2 := make([]byte, KeySize)
	rand.Read(key2)
	aead2 := newXChaCha20(t, key2)
	eof := SealEOF(aead2, base, 0)

	_, err := OpenChunk(aead, eof, base, 0)
	if err != ErrEOFMarkerInvalid {
		t.Fatalf("expected ErrEOFMarkerInvalid, got: %v", err)
	}
}

func TestOpenChunkTruncatedSealed(t *testing.T) {
	key := make([]byte, KeySize)
	rand.Read(key)
	aead := newXChaCha20(t, key)

	var base [NonceSize]byte
	_, err := OpenChunk(aead, []byte{1, 2, 3}, base, 0)
	if err == nil {
		t.Fatal("expected error for truncated sealed data (< 4 bytes)")
	}
}

func TestOpenChunkTruncatedData(t *testing.T) {
	key := make([]byte, KeySize)
	rand.Read(key)
	aead := newXChaCha20(t, key)

	var base [NonceSize]byte
	// chunkLen=1000 but only 10 bytes provided
	sealed := make([]byte, 14)
	binary.LittleEndian.PutUint32(sealed[:4], 1000)
	copy(sealed[4:], "shortdata")

	_, err := OpenChunk(aead, sealed, base, 0)
	if err == nil {
		t.Fatal("expected error for truncated chunk data")
	}
}

func TestSealEOF(t *testing.T) {
	key := make([]byte, KeySize)
	rand.Read(key)
	aead := newXChaCha20(t, key)

	var base [NonceSize]byte
	rand.Read(base[:])

	eof := SealEOF(aead, base, 0)
	if len(eof) < 5 {
		t.Fatalf("EOF marker too short: %d bytes", len(eof))
	}
	// First 4 bytes must be zero
	if eof[0] != 0 || eof[1] != 0 || eof[2] != 0 || eof[3] != 0 {
		t.Error("EOF marker first 4 bytes should be zero")
	}
}

func newXChaCha20(t *testing.T, key []byte) cipher.AEAD {
	t.Helper()
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		t.Fatalf("NewX: %v", err)
	}
	return aead
}

func TestParseHeaderReadError(t *testing.T) {
	// A reader that returns an error
	r := &errReader{err: io.ErrClosedPipe}
	_, err := ParseHeader(r)
	if err == nil {
		t.Fatal("expected error")
	}
}

type errReader struct {
	err error
}

func (r *errReader) Read(p []byte) (int, error) {
	return 0, r.err
}

func TestSealChunkRoundTripMultiple(t *testing.T) {
	key := make([]byte, KeySize)
	rand.Read(key)
	aead := newXChaCha20(t, key)

	var base [NonceSize]byte
	rand.Read(base[:])

	sizes := []int{1, 16, 1024, 65536}
	for _, size := range sizes {
		pt := make([]byte, size)
		rand.Read(pt)

		sealed := SealChunk(aead, pt, base, uint64(size))
		result, err := OpenChunk(aead, sealed, base, uint64(size))
		if err != nil {
			t.Fatalf("size=%d OpenChunk: %v", size, err)
		}
		if !bytes.Equal(result, pt) {
			t.Fatalf("size=%d: round-trip mismatch", size)
		}
	}
}