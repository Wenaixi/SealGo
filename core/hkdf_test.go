package core

import (
	"bytes"
	"testing"
)

func TestHKDF_SameInputsSameOutput(t *testing.T) {
	masterKey := []byte("0123456789abcdef")
	info := "test-info"
	outLen := 32

	key1 := HkdfDerive(masterKey, info, outLen)
	key2 := HkdfDerive(masterKey, info, outLen)

	if !bytes.Equal(key1, key2) {
		t.Errorf("same inputs should produce same output: got %x vs %x", key1, key2)
	}
}

func TestHKDF_DifferentInfoProducesDifferentKeys(t *testing.T) {
	masterKey := []byte("0123456789abcdef")
	outLen := 32

	key1 := HkdfDerive(masterKey, "info-a", outLen)
	key2 := HkdfDerive(masterKey, "info-b", outLen)

	if bytes.Equal(key1, key2) {
		t.Errorf("different info should produce different keys")
	}
}

func TestHKDF_OutputLengthCorrect(t *testing.T) {
	masterKey := []byte("0123456789abcdef")
	info := "test-info"

	testCases := []int{16, 32, 64, 128}

	for _, outLen := range testCases {
		key := HkdfDerive(masterKey, info, outLen)
		if len(key) != outLen {
			t.Errorf("expected length %d, got %d", outLen, len(key))
		}
	}
}