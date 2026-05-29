package stream

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"SealGo/core"
)

func TestEncryptDecryptWithRecipients(t *testing.T) {
	// Generate a keypair.
	pub, priv, err := core.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	recipient := &core.X25519Recipient{PubKey: pub}
	identity := &core.X25519Identity{PrivKey: priv}

	// Use enough plaintext to produce at least one chunk.
	plaintext := make([]byte, 200)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	// Encrypt.
	var encrypted bytes.Buffer
	ew, err := NewEncryptWriterWithRecipients(&encrypted, []core.Recipient{recipient}, core.DefaultChunkSize, nil, "", nil)
	if err != nil {
		t.Fatalf("NewEncryptWriterWithRecipients: %v", err)
	}
	if _, err := ew.Write(plaintext); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := ew.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Decrypt.
	dr, _, err := NewDecryptReaderWithIdentity(bytes.NewReader(encrypted.Bytes()), []core.Identity{identity})
	if err != nil {
		t.Fatalf("NewDecryptReaderWithIdentity: %v", err)
	}
	decrypted, err := io.ReadAll(dr)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatal("decrypted data does not match original plaintext")
	}
}

func TestEncryptDecryptMultipleRecipients(t *testing.T) {
	const numRecipients = 3

	// Generate 3 keypairs.
	pubs := make([][32]byte, numRecipients)
	privs := make([][32]byte, numRecipients)
	for i := 0; i < numRecipients; i++ {
		pub, priv, err := core.GenerateKeypair()
		if err != nil {
			t.Fatalf("GenerateKeypair %d: %v", i, err)
		}
		pubs[i] = pub
		privs[i] = priv
	}

	plaintext := make([]byte, 200)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	// Encrypt to all 3 recipients.
	recipients := make([]core.Recipient, numRecipients)
	for i := 0; i < numRecipients; i++ {
		recipients[i] = &core.X25519Recipient{PubKey: pubs[i]}
	}

	var encrypted bytes.Buffer
	ew, err := NewEncryptWriterWithRecipients(&encrypted, recipients, core.DefaultChunkSize, nil, "", nil)
	if err != nil {
		t.Fatalf("NewEncryptWriterWithRecipients: %v", err)
	}
	if _, err := ew.Write(plaintext); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := ew.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	encryptedData := encrypted.Bytes()

	// Each recipient can decrypt independently.
	for i := 0; i < numRecipients; i++ {
		identity := &core.X25519Identity{PrivKey: privs[i]}
		dr, _, err := NewDecryptReaderWithIdentity(bytes.NewReader(encryptedData), []core.Identity{identity})
		if err != nil {
			t.Errorf("recipient %d: NewDecryptReaderWithIdentity: %v", i, err)
			continue
		}
		decrypted, err := io.ReadAll(dr)
		if err != nil {
			t.Errorf("recipient %d: ReadAll: %v", i, err)
			continue
		}
		if !bytes.Equal(plaintext, decrypted) {
			t.Errorf("recipient %d: decrypted data mismatch", i)
		}
	}
}

func TestDecryptWithWrongIdentity(t *testing.T) {
	// Generate keypair for encryption.
	pub, _, err := core.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	// Generate a DIFFERENT keypair for attempted decryption.
	_, wrongPriv, err := core.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair wrong: %v", err)
	}

	recipient := &core.X25519Recipient{PubKey: pub}
	wrongIdentity := &core.X25519Identity{PrivKey: wrongPriv}

	plaintext := make([]byte, 200)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	// Encrypt.
	var encrypted bytes.Buffer
	ew, err := NewEncryptWriterWithRecipients(&encrypted, []core.Recipient{recipient}, core.DefaultChunkSize, nil, "", nil)
	if err != nil {
		t.Fatalf("NewEncryptWriterWithRecipients: %v", err)
	}
	if _, err := ew.Write(plaintext); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := ew.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Decrypt with wrong identity.
	_, _, err = NewDecryptReaderWithIdentity(bytes.NewReader(encrypted.Bytes()), []core.Identity{wrongIdentity})
	if err == nil {
		t.Fatal("expected error when decrypting with wrong identity, got nil")
	}
	t.Logf("wrong identity error (expected): %v", err)
}

func TestEncryptDecryptLargeData(t *testing.T) {
	pub, priv, err := core.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	recipient := &core.X25519Recipient{PubKey: pub}
	identity := &core.X25519Identity{PrivKey: priv}

	// Large plaintext to test multi-chunk streaming.
	plaintext := make([]byte, 256*1024) // 256 KB, ~4 chunks
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	var encrypted bytes.Buffer
	ew, err := NewEncryptWriterWithRecipients(&encrypted, []core.Recipient{recipient}, core.DefaultChunkSize, nil, "", nil)
	if err != nil {
		t.Fatalf("NewEncryptWriterWithRecipients: %v", err)
	}
	if _, err := ew.Write(plaintext); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := ew.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	dr, _, err := NewDecryptReaderWithIdentity(bytes.NewReader(encrypted.Bytes()), []core.Identity{identity})
	if err != nil {
		t.Fatalf("NewDecryptReaderWithIdentity: %v", err)
	}
	decrypted, err := io.ReadAll(dr)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatal("decrypted data does not match original plaintext")
	}
}

func TestEncryptDecryptEmptyData(t *testing.T) {
	pub, priv, err := core.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	recipient := &core.X25519Recipient{PubKey: pub}
	identity := &core.X25519Identity{PrivKey: priv}

	var encrypted bytes.Buffer
	ew, err := NewEncryptWriterWithRecipients(&encrypted, []core.Recipient{recipient}, core.DefaultChunkSize, nil, "", nil)
	if err != nil {
		t.Fatalf("NewEncryptWriterWithRecipients: %v", err)
	}
	if err := ew.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	dr, _, err := NewDecryptReaderWithIdentity(bytes.NewReader(encrypted.Bytes()), []core.Identity{identity})
	if err != nil {
		t.Fatalf("NewDecryptReaderWithIdentity: %v", err)
	}
	decrypted, err := io.ReadAll(dr)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(decrypted) != 0 {
		t.Fatalf("expected empty output, got %d bytes", len(decrypted))
	}
}

func TestCorruptedHeaderRejected(t *testing.T) {
	pub, priv, err := core.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	recipient := &core.X25519Recipient{PubKey: pub}
	identity := &core.X25519Identity{PrivKey: priv}

	plaintext := []byte("hello")
	var encrypted bytes.Buffer
	ew, err := NewEncryptWriterWithRecipients(&encrypted, []core.Recipient{recipient}, core.DefaultChunkSize, nil, "", nil)
	if err != nil {
		t.Fatalf("NewEncryptWriterWithRecipients: %v", err)
	}
	ew.Write(plaintext)
	ew.Close()

	data := encrypted.Bytes()
	// Corrupt the magic
	data[0] = 'X'

	_, _, err = NewDecryptReaderWithIdentity(bytes.NewReader(data), []core.Identity{identity})
	if err == nil {
		t.Fatal("expected error for corrupted header")
	}
}

func TestCorruptedDataRejected(t *testing.T) {
	pub, priv, err := core.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	recipient := &core.X25519Recipient{PubKey: pub}
	identity := &core.X25519Identity{PrivKey: priv}

	plaintext := []byte("sensitive data")
	var encrypted bytes.Buffer
	ew, err := NewEncryptWriterWithRecipients(&encrypted, []core.Recipient{recipient}, core.DefaultChunkSize, nil, "", nil)
	if err != nil {
		t.Fatalf("NewEncryptWriterWithRecipients: %v", err)
	}
	ew.Write(plaintext)
	ew.Close()

	data := encrypted.Bytes()
	// Corrupt a byte in the first chunk data (after header + first chunk)
	if len(data) > 120 {
		data[len(data)-10] ^= 0xFF
	}

	dr, _, err := NewDecryptReaderWithIdentity(bytes.NewReader(data), []core.Identity{identity})
	if err != nil {
		t.Fatalf("NewDecryptReaderWithIdentity: %v", err)
	}
	_, err = io.ReadAll(dr)
	if err == nil {
		t.Fatal("expected error for corrupted data")
	}
}